<?php
/**
 * SpecialOAuth2Client.php
 * Based on TwitterLogin by David Raison, which is based on the guideline published by Dave Challis at http://blogs.ecs.soton.ac.uk/webteam/2010/04/13/254/
 * @license: LGPL (GNU Lesser General Public License) http://www.gnu.org/licenses/lgpl.html
 *
 * @file SpecialOAuth2Client.php
 * @ingroup OAuth2Client
 *
 * @author Joost de Keijzer
 * @author Nischay Nahata for Schine GmbH
 *
 * Uses the OAuth2 library https://github.com/vznet/oauth_2.0_client_php
 *
 */

if ( !defined( 'MEDIAWIKI' ) ) {
	die( 'This is a MediaWiki extension, and must be run from within MediaWiki.' );
}

class SpecialOAuth2Client extends SpecialPage {

	private $_provider;

	/**
	 * Required settings in global $wgOAuth2Client
	 *
	 * $wgOAuth2Client['client']['id']
	 * $wgOAuth2Client['client']['secret']
	 * //$wgOAuth2Client['client']['callback_url'] // extension should know
	 *
	 * //$wgOAuth2Client['configuration']['authorize_endpoint'] // extension should know
	 * //$wgOAuth2Client['configuration']['access_token_endpoint'] // extension should know
	 * $wgOAuth2Client['configuration']['http_bearer_token']
	 * $wgOAuth2Client['configuration']['query_parameter_token']
	 * //$wgOAuth2Client['configuration']['api_endpoint'] // extension should know
	 */
	public function __construct() {

		parent::__construct('OAuth2Client'); // ???: wat doet dit?
		global $wgOAuth2Client, $wgScriptPath;
		global $wgServer, $wgArticlePath;

		require __DIR__ . '/vendors/oauth2-client/vendor/autoload.php';

        // default to 'identify' scope
		$scopes = $wgOAuth2Client['configuration']['scopes']
            ? $wgOAuth2Client['configuration']['scopes']
            : 'identify';

		$this->_provider = new \League\OAuth2\Client\Provider\GenericProvider([
			'clientId'                => $wgOAuth2Client['client']['id'],    // The client ID assigned to you by the provider
			'clientSecret'            => $wgOAuth2Client['client']['secret'],   // The client password assigned to you by the provider
			'redirectUri'             => $wgOAuth2Client['configuration']['redirect_uri'],
			'scopes'                  => $scopes,
			'urlAuthorize'            => 'https://discordapp.com/api/oauth2/authorize',
			'urlAccessToken'          => 'https://discordapp.com/api/oauth2/token',
			'urlResourceOwnerDetails' => 'https://discordapp.com/api/users/@me'
		]);
	}

	// default method being called by a specialpage
	public function execute( $parameter ){
		$this->setHeaders();
		switch($parameter){
			case 'redirect':
				$this->_redirect();
			break;
			case 'callback':
				$this->_handleCallback();
			break;
			default:
				$this->_default();
			break;
		}

	}

	private function _redirect() {

		global $wgRequest, $wgOut;
		$wgRequest->getSession()->persist();
		$wgRequest->getSession()->set('returnto', $wgRequest->getVal( 'returnto' ));

		// Fetch the authorization URL from the provider; this returns the
		// urlAuthorize option and generates and applies any necessary parameters
		// (e.g. state).
		$authorizationUrl = $this->_provider->getAuthorizationUrl();

		// Get the state generated for you and store it to the session.
		$wgRequest->getSession()->set('oauth2state', $this->_provider->getState());
		$wgRequest->getSession()->save();

		// Redirect the user to the authorization URL.
		$wgOut->redirect( $authorizationUrl );
	}

	private function _handleCallback(){
		global $wgRequest;

		try {
			$storedState = $wgRequest->getSession()->get('oauth2state');
			// Enforce the `state` parameter to prevent clickjacking/CSRF
			if(isset($storedState) && $storedState != $_GET['state']) {
				if(isset($_GET['state'])) {
					throw new UnexpectedValueException("State parameter of callback does not match original state");
				} else {
					throw new UnexpectedValueException("Required state parameter missing");
				}
			}

			// Try to get an access token using the authorization code grant.
			$accessToken = $this->_provider->getAccessToken('authorization_code', [
				'code' => $_GET['code']
			]);
		} catch (\League\OAuth2\Client\Provider\Exception\IdentityProviderException $e) {
			exit($e->getMessage()); // Failed to get the access token or user details.
		} catch (UnexpectedValueException $e) {
			exit($e->getMessage());
		}

		$response = $this->_provider->getResourceOwner($accessToken)->toArray();
		$this->_userHandling($accessToken, $response);

		global $wgOut, $wgRequest;
		$title = null;
		$wgRequest->getSession()->persist();
		if( $wgRequest->getSession()->exists('returnto') ) {
			$title = Title::newFromText( $wgRequest->getSession()->get('returnto') );
			$wgRequest->getSession()->remove('returnto');
			$wgRequest->getSession()->save();
		}

		if( !$title instanceof Title || 0 > $title->mArticleID ) {
			$title = Title::newMainPage();
		}
		$wgOut->redirect( $title->getFullURL() );
		return true;
	}

	private function _default(){
		global $wgOAuth2Client, $wgOut, $wgUser, $wgScriptPath, $wgExtensionAssetsPath;
		$service_name = ( isset( $wgOAuth2Client['configuration']['service_name'] ) && 0 < strlen( $wgOAuth2Client['configuration']['service_name'] ) ? $wgOAuth2Client['configuration']['service_name'] : 'Discord' );

		$wgOut->setPagetitle( wfMessage( 'oauth2client-login-header', $service_name)->text() );
		if ( !$wgUser->isLoggedIn() ) {
			$wgOut->addWikiMsg( 'oauth2client-you-can-login-to-this-wiki-with-oauth2', $service_name );
			$wgOut->addWikiMsg( 'oauth2client-login-with-oauth2', $this->getTitle( 'redirect' )->getPrefixedURL(), $service_name );

		} else {
			$wgOut->addWikiMsg( 'oauth2client-youre-already-loggedin' );
		}
		return true;
	}

	/*  @brief  Returns a MW::User from the provided accessToken and response.
	* 
	*  @param  $accessToken  [
	*	  'accessToken' => 'examples0zEeL7JedtrxONjkCDVRDM',
	*	  'expires' => 1572514877,
	*	  'refreshToken' => 'exampleW85x7p5qX6VL0WySMEtcdQ4',
	*	  'resourceOwnerId' => NULL,
	*	  'values' => [
	*		  'scope' => 'identify email',
	*		  'token_type' => 'Bearer'
	*	  ]
	*  ]
	*  @param  $response  [
	*	  'username' => 'Example',
	*	  'verified' => true,
	*	  'locale' => 'en-US',
	*	  'mfa_enabled' => true,
	*	  'id' => '123456789123456789',
	*	  'flags' => 0,
	*	  'avatar' => 'example1d39b4ffc5d38b7c5694459f8',
	*	  'discriminator' => '1234',
	*	  'email' => 'requiresEmailScope@example.com'
	*  ]
	*/
	protected function _userHandling($accessToken, $response) {
		global $wgOAuth2Client, $wgAuth, $wgRequest;

		$username = $response['username'];

		// change square brackets to parentheses
		$username = str_replace('[', '(', $username);
		$username = str_replace(']', ')', $username);

		// https://www.mediawiki.org/wiki/Manual:Title.php#Article_name
		//   "Extended" characters in the 0x80..0xFF range are allowed. Other characters may be ASCII
		//   letters, digits, hyphen, comma, period, apostrophe, parentheses, and colon.
		//   No other ASCII characters are allowed, and will be deleted if found.
		$username = preg_replace('/[^\x80-\xFF\w\ \-\,\.\'\"\(\)\:]/', '', $username);

		// load user from username, create it if it doesn't exist
		$user = User::newFromName($username, 'creatable');
		if (!$user) {
			throw new MWException('Could not create user with username:' . $username);
			die();
		}
		$user->setRealName($username);

		if (isset($response['email'])) {
			$email = $response['email'];
			$user->setEmail($email);
		}

		$user->load();
		if ( !( $user instanceof User && $user->getId() ) ) {
			$user->addToDatabase();
			// MediaWiki recommends below code instead of addToDatabase to create user but it seems to fail.
			// $authManager = MediaWiki\Auth\AuthManager::singleton();
			// $authManager->autoCreateUser( $user, MediaWiki\Auth\AuthManager::AUTOCREATE_SOURCE_SESSION );
			if (isset($response['email'])) {
				$user->confirmEmail();
			}
		}

		// Setup the session
		$wgRequest->getSession()->persist();
		$user->setToken();
		$user->setCookies();
		$user->saveSettings();
		$this->getContext()->setUser( $user );

		global $wgUser;
		$wgUser = $user;
		$sessionUser = User::newFromSession($this->getRequest());
		$sessionUser->load();
	}

}
