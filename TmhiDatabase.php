<?php
require_once __DIR__.'/TmhiMember.php';

class TmhiDatabase {
    private $_conn;

	public function __construct($dbHost, $dbDatabase, $dbUser, $dbPassword) {
        // open the database using provided credentials
        $this->_conn = new PDO("mysql:host=$dbHost;dbname=$dbDatabase", $dbUser, $dbPassword);

        // set the PDO error mode to exception
        $this->_conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
	}

	public function storeAccessToken($discordId, $accessToken)	{
        $token        = $accessToken->getToken();
        $expires      = $accessToken->getExpires();
        $refreshToken = $accessToken->getRefreshToken();

        $statement = $this->_conn->prepare('
            INSERT INTO users (id, discordtoken, discordtokenexpires, discordrefreshtoken)
            VALUES (:id, :token, :tokenexpires, :refreshtoken)
            ON DUPLICATE KEY
            UPDATE discordtoken=:token, discordtokenexpires=:tokenexpires, discordrefreshtoken=:refreshtoken
        ');
        $statement->execute([
            'id'           => $discordId,
            'token'        => $token,
            'tokenexpires' => $expires,
            'refreshtoken' => $refreshToken,
        ]);
	}

	public function storeTmhiMember($tmhiMember) {
        $statement = $this->_conn->prepare('
            UPDATE users
            SET wikiid=:wikiid, email=:email
            WHERE id=:discordid
        ');
        $statement->execute([
            'wikiid'    => $tmhiMember->wikiId,
            'email'     => $tmhiMember->email,
            'discordid' => $tmhiMember->discordId,
        ]);
    }
    
    /*
    * Retrieve a Discord user from the database.
    *
    * @param    discordId  The Discord Snowflake ID of the user to load from the database.
    * @returns  A TmhiMember object.
    */
	public function loadTmhiMember($discordId) {
        // load user
        $statement = $this->_conn->prepare('
            SELECT displayname, wikiid, email, timezone
            FROM users
            WHERE id=:discordid
        ');
        $statement->execute([
            'discordid' => $discordId,
        ]);
        $row = $statement->fetch(PDO::FETCH_ASSOC);

        // no user found
        if (!$row) {
            return false;
        }
        $displayName = $row['displayname'];
        $wikiid      = $row['wikiid'];
        $email       = $row['email'];
        $timezone    = $row['timezone'];

        // load roles for user
        $statement = $this->_conn->prepare('
            SELECT roles.id as id, roles.name as name, roles.description as description
            FROM userroles
            JOIN roles ON userroles.roleid=roles.id
            WHERE userroles.userid=:discordid
        ');
        $statement->execute([
            'discordid' => $discordId,
        ]);
        $rows = $statement->fetchAll(PDO::FETCH_ASSOC);
        var_dump($rows);

        // map roles into an array
        $roles = [];
        foreach ($rows as $row) {
            $roles[$row['id']] = [
                name        => $row['name'],
                description => $row['description'],
            ];
        }

        // load permissions for user (if the user has at least one role)
        $permissions = [];
        if (count($roles)) {
            $statement = $this->_conn->prepare('
                SELECT permissions.id as id, permissions.name as name, permissions.description as description
                FROM rolepermissions
                JOIN permissions ON rolepermissions.permissionid=permissions.id
                WHERE rolepermissions.roleid IN (' . join(',', array_fill(0, count($roles), '?')) . ')
            ');
            $statement->execute(array_keys($roles));
            $rows = $statement->fetchAll(PDO::FETCH_ASSOC);
    
            // map permissions into an array
            foreach ($rows as $row) {
                $permissions[$row['id']] = [
                    name        => $row['name'],
                    description => $row['description'],
                ];
            }
        }

		return new TmhiMember(
            $discordId,
            $displayName,
            $permissions,
            $wikiid,
            $email,
            $timezone
        );
	}
}
