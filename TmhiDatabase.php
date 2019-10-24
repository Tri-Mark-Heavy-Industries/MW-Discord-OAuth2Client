<?php
require_once __DIR__.'/DiscordUser.php';

class TmhiDatabase {
    private $_conn;

	public function __construct($dbHost, $dbDatabase, $dbUser, $dbPassword) {
        // open the database using provided credentials
        $this->_conn = new PDO("mysql:host=$dbHost;dbname=$dbDatabase", $dbUser, $dbPassword);

        // set the PDO error mode to exception
        $this->_conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
	}

	public function storeAccessToken($discordId, $accessToken)	{
        $token = $accessToken->getToken();
        $expires = $accessToken->getExpires();
        $refreshToken = $accessToken->getRefreshToken();

        $statement = $this->_conn->prepare('
            INSERT INTO users (discordid, discordtoken, discordtokenexpires, discordrefreshtoken)
            VALUES (:discordid, :token, :tokenexpires, :refreshtoken)
            ON DUPLICATE KEY
            UPDATE discordtoken = :token, discordtokenexpires = :tokenexpires, discordrefreshtoken = :refreshtoken
        ');

        $statement->execute([
            'discordid' => $discordId,
            'token' => $token,
            'tokenexpires' => $expires,
            'refreshtoken' => $refreshToken,
        ]);
	}

	public function storeDiscordUser($discordUser) {
        $statement = $this->_conn->prepare('
            UPDATE users
            SET wikiid=:wikiid, email=:email
            WHERE discordid=:discordid
        ');

        $statement->execute([
            'wikiid' => $discordUser->getWikiId(),
            'email' => $discordUser->getEmail(),
            'discordid' => $discordUser->getDiscordId(),
        ]);
	}

	public function getDiscordUserById($discordId) {
        $statement = $this->_conn->prepare('
            SELECT displayname, permissions, wikiid, email
            FROM users
            WHERE discordid=:discordid
        ');

        $statement->execute([
            'discordid' => $discordId,
        ]);

        $result = $statement->fetch(PDO::FETCH_ASSOC);

        // no user found
        if (!$result) {
            return false;
        }

		return new DiscordUser(
            $discordId,
            $result['displayname'],
            (int) $result['permissions'],
            (int) $result['wikiid'],
            $result['email']
        );
	}
}
