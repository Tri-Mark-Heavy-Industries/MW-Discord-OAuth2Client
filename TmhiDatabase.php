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

    /**
     * Create, bind, execute and fetch a single result of a SQL query
     * @param string $sql The query to execute
     * @param string $params Parameters to bind
     * @param array A single result in a named array
     */
    private function _query($sql, $params) {
        $statement = $this->_conn->prepare($sql);
        $statement->execute($params);
        return $statement->fetch(PDO::FETCH_ASSOC);
    }

    /**
     * Create, bind, execute and fetch all results of a SQL query
     * @param string $sql The query to execute
     * @param string $params Parameters to bind
     * @param array[] An array of results in named arrays
     */
    private function _queryAll($sql, $params) {
        $statement = $this->_conn->prepare($sql);
        $statement->execute($params);
        return $statement->fetchAll(PDO::FETCH_ASSOC);
    }
    
    /**
     * Store a Discord member's access token
     * @param Snowflake $guildMember The member who owns the access token
     * @param League\OAuth2\Client\Token\AccessToken $accessToken The access token to store
     */
    public function storeAccessToken($discordId, $accessToken)    {
        $token        = $accessToken->getToken();
        $expires      = $accessToken->getExpires();
        $refreshToken = $accessToken->getRefreshToken();

        $this->_query('
            INSERT INTO members (id, discordtoken, discordtokenexpires, discordrefreshtoken)
            VALUES (:id, :token, :tokenExpires, :refreshToken)
            ON DUPLICATE KEY
            UPDATE discordtoken=:token, discordtokenexpires=:tokenExpires, discordrefreshtoken=:refreshToken
        ', [
            'id'           => $discordId,
            'token'        => $token,
            'tokenExpires' => $expires,
            'refreshToken' => $refreshToken,
        ]);
    }

    /**
     * Store a T-MHI member
     * @param TmhiMember $tmhiMember The member to add
     */
    public function storeTmhiMember($tmhiMember) {
        $this->_query('
            UPDATE members
            SET wikiid=:wikiId, email=:email
            WHERE id=:discordId
        ', [
            'wikiId'    => $tmhiMember->wikiId,
            'email'     => $tmhiMember->email,
            'discordId' => $tmhiMember->discordId,
        ]);
    }
    
    /**
    * Retrieve a T-MHI member from the database
    * @param Snowflake $discordId The Discord Snowflake ID of the user
    * @return TmhiMember The requested member
    */
    public function loadTmhiMember($discordId) {
        // load user
        $row = $this->_query('
            SELECT displayname, wikiid, email, timezone
            FROM members
            WHERE id=:discordId
        ', [ 'discordId' => $discordId ]);

        // no user found
        if (!$row) {
            return false;
        }
        $displayName = $row['displayname'];
        $wikiId      = $row['wikiid'];
        $email       = $row['email'];
        $timezone    = $row['timezone'];

        // load roles for user
        $rows = $this->_queryAll('
            SELECT id, roles.guildid, name, roles.comment, hexcolor, discordpermissions
            FROM memberroles
            JOIN roles ON memberroles.roleid=roles.id
            WHERE memberroles.memberid=:discordId
        ', [ 'discordId' => $discordId ]);

        // map roles into an array
        $roles = [];
        foreach ($rows as $row) {
            $roles[$row['id']] = [
                'id'                 => $row['id'],
                'uniqueId'           => $row['guildid'] . $row['id'],
                'name'               => $row['name'],
                'guildId'            => $row['guildid'],
                'comment'            => $row['comment'],
                'hexcolor'           => $row['hexcolor'],
                'discordPermissions' => $row['discordpermissions'],
            ];
        }

        $permissions = [];

        // load personal permissions for the user
        $rows = $this->_queryAll('
            SELECT id, permissions.guildid, name, permissions.comment
            FROM memberpermissions
            JOIN permissions ON rolepermissions.permissionid=permissions.id
            WHERE memberpermissions.memberid=:discordId
        ', [ 'discordId' => $discordId ]);

        // map permissions into an array
        foreach ($rows as $row) {
            $permissions[$row['id']] = [
                'id'      => $row['id'],
                'guildid' => $row['guildid'],
                'name'    => $row['name'],
                'comment' => $row['comment'],
            ];
        }

        // load role-based permissions for user
        if (count($roles)) {
            $rows = $this->_queryAll('
                SELECT id, permissions.guildid, name, permissions.comment
                FROM rolepermissions
                JOIN permissions ON rolepermissions.permissionid=permissions.id
                WHERE CONCAT(rolepermissions.guildid, rolepermissions.roleid) IN (' . join(',', array_fill(0, count($roles), '?')) . ')
            ', array_column($roles, 'uniqueId'));
    
            // map permissions into an array
            foreach ($rows as $row) {
                $permissions[$row['id']] = [
                    'id'      => $row['id'],
                    'guildid' => $row['guildid'],
                    'name'    => $row['name'],
                    'comment' => $row['comment'],
                ];
            }
        }

        return new TmhiMember(
            $discordId,
            $displayName,
            $permissions,
            $wikiId,
            $email,
            $timezone
        );
    }
}
