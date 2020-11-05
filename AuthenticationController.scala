package controllers

import java.math.BigInteger
import java.security.SecureRandom
import java.util.UUID.randomUUID

import javax.inject.Inject
import models.Auth0Config
import play.api.Configuration
import play.api.cache._
import play.api.http.{HeaderNames, MimeTypes}
import play.api.libs.json.Json.toJsFieldJsValueWrapper
import play.api.libs.json.{JsValue, Json}
import play.api.libs.ws._
import play.api.mvc._

import scala.concurrent.{ExecutionContext, Future}

class AuthenticationController @Inject()(cache: SyncCacheApi,
                                         ws: WSClient,
                                         configuration: Configuration,
                                         cc: MessagesControllerComponents)(implicit ec: ExecutionContext)
  extends MessagesAbstractController(cc) {

  private val config = Auth0Config.get(configuration)

  def callback(codeOpt: Option[String] = None, stateOpt: Option[String] = None): Action[AnyContent] = Action.async { request =>
    val sessionId = request.session.get("id").get
    if (stateOpt == cache.get(sessionId + "state")) {
      //println("stateOpt: " + stateOpt)
      (for {
        code <- codeOpt
      } yield {
        getToken(code, sessionId).flatMap { case (idToken, accessToken) =>
          getUser(accessToken).map { user =>
            Redirect(routes.PatientController.patientIndex()).withSession(
              idToken + "profile" -> user.toString() )
          }
        }.recover {
          case ex: IllegalStateException => Unauthorized(ex.getMessage)
        }
      }).getOrElse(Future.successful(BadRequest("No user authorization")))
    } else {
      Future.successful(BadRequest("Invalid state parameter"))
    }
  }

  def getToken(code: String, sessionId: String): Future[(String, String)] = {
    var audience = config.audience
    if (config.audience == ""){
      audience = String.format("https://%s/userinfo",config.domain)
    }
    val tokenResponse = ws.url(String.format("https://%s/oauth/token", config.domain)).
      withHttpHeaders(HeaderNames.ACCEPT -> MimeTypes.JSON).
      post(
        Json.obj(
          "client_id" -> config.clientId,
          "client_secret" -> config.secret,
          "redirect_uri" -> config.callbackURL,
          "code" -> code,
          "grant_type"-> "authorization_code",
          "audience" -> audience
        )
      )

    tokenResponse.flatMap { response =>
      (for {
        idToken <- (response.json \ "id_token").asOpt[String]
        accessToken <- (response.json \ "access_token").asOpt[String]
      } yield {
        Future.successful((idToken, accessToken))
      }).getOrElse(Future.failed[(String, String)](new IllegalStateException("Tokens not sent")))
    }

  }

  def getUser(accessToken: String): Future[JsValue] = {
    val userResponse = ws.url(String.format("https://%s/userinfo", config.domain))
      .withQueryStringParameters("access_token" -> accessToken)
      .get()

    userResponse.flatMap(response => Future.successful(response.json))
  }

  def login: Action[AnyContent] = Action {
    // Generate random state parameter
    object RandomUtil {
      private val random = new SecureRandom()

      def alphanumeric(nrChars: Int = 24): String = {
        new BigInteger(nrChars * 5, random).toString(32)
      }
    }
    val state = RandomUtil.alphanumeric()

    var audience = config.audience
    if (config.audience == ""){
      audience = String.format("https://%s/userinfo", config.domain)
    }

    val id = randomUUID().toString
    cache.set(id + "state", state)
    val query = String.format(
      "authorize?client_id=%s&redirect_uri=%s&response_type=code&scope=openid profile&audience=%s&state=%s",
      config.clientId,
      config.callbackURL,
      audience,
      state
    )
    Redirect(String.format("https://%s/%s", config.domain, query)).withSession("id" -> id)
  }


  def AuthenticatedAction(implicit f: MessagesRequest[AnyContent] => Result): Action[AnyContent] = {
    Action { request =>
      val idToken = request.session.get("idToken").get
      request.session.get(idToken + "profile").map { _ =>
        f(request)
      }.orElse {
        //println("not logged in!!!")
        Some(Redirect(routes.PatientController.patientIndex).flashing("warning" -> "login.reminder"))
      }.get
    }
  }

  def displayUserInfo: Action[AnyContent] = AuthenticatedAction { implicit request =>
    val idToken = request.session.get("idToken").get
    val profile = Json.parse(request.session.get(idToken + "profile").get)
    //println(profile)
    Ok(views.html.displayUserInfo(profile))
  }

  def logout: Action[AnyContent] = Action { request =>
    val host = request.host
    var scheme = "http"
    if (request.secure) {
      scheme = "https"
    }
    val returnTo = scheme + "://" + host
    Redirect(String.format(
      "https://%s/v2/logout?client_id=%s&returnTo=%s",
      config.domain,
      config.clientId,
      returnTo)
    ).withNewSession.flashing("success" -> "logout.confirmation")
  }
}