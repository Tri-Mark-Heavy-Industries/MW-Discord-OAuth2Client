# MediaWiki T-MHI Discord OAuth2 Client
A T-MHI fork of the [MediaWiki Discord OAuth2 Client](https://github.com/DarkMatterMatt/MW-Discord-OAuth2Client).

Requires MediaWiki 1.25+.

## Installation

Clone this repo into the extension directory. In the cloned directory, run `git submodule update --init` to initialize the local configuration file and fetch all data from the OAuth2 client library.

Finally, run [composer](https://getcomposer.org/) in /vendors/oauth2-client to install the library dependency.

```
composer install
```

## Usage

Add the following line to your LocalSettings.php file.

```
wfLoadExtension('MW-TMHI-Discord-OAuth2Client');
```

Required settings to be added to LocalSettings.php

```
$wgOAuth2Client['client']['id']     = ''; // The client ID assigned to you by the provider
$wgOAuth2Client['client']['secret'] = ''; // The client secret assigned to you by the provider
$wgOAuth2Client['configuration']['redirect_uri'] = ''; // URL for OAuth2 server to redirect to
$wgOAuth2Client['configuration']['scopes'] = 'identity'; // Permissions, refer to https://discordapp.com/developers/docs/topics/oauth2#shared-resources-oauth2-scopes

$wgWhitelistRead = ['Main Page', 'Special:UserLogin', 'Special:OAuth2Client', 'Special:OAuth2Client/redirect', 'Request Wiki Access', 'Join T-MHI'];
```

The **Redirect URI** for your wiki should be:

```
http://your.wiki.domain/path/to/wiki/Special:OAuth2Client/callback
```

Optional further configuration

```
$wgOAuth2Client['configuration']['http_bearer_token'] = 'Bearer'; // Token to use in HTTP Authentication
$wgOAuth2Client['configuration']['query_parameter_token'] = 'auth_token'; // query parameter to use

$wgOAuth2Client['configuration']['service_name'] = 'Discord'; // the name of your service
$wgOAuth2Client['configuration']['service_login_link_text'] = 'Login with Discord'; // the text of the login link

```

### Popup Window
To use a popup window to login to the external OAuth2 server, copy the JS from modal.js to the [MediaWiki:Common.js](https://www.mediawiki.org/wiki/Manual:Interface/JavaScript) page on your wiki.

### Extension page
https://www.mediawiki.org/wiki/Extension:OAuth2_Client

## License
LGPL (GNU Lesser General Public License) http://www.gnu.org/licenses/lgpl.html
