<?php

class TmhiMember {
    // permission IDs
    private const GOD_MODE    = 'GOD_MODE';
    private const WIKI_ACCESS = 'WIKI_ACCESS';

    public $discordId;
    public $displayName;
    public $tmhiPermissions;
    public $wikiId;
    public $email;
    public $timezone;

    public function __construct($discordId, $displayName, $permissions = [], $wikiId = 0, $email = '', $timezone = '') {
        $this->discordId       = $discordId;
        $this->displayName     = $displayName;
        $this->tmhiPermissions = $permissions;
        $this->wikiId          = $wikiId;
        $this->email           = $email;
        $this->timezone        = $timezone;
    }

    private function hasPermission($permission) {
        if (array_key_exists(self::GOD_MODE, $this->tmhiPermissions)) {
            return true;
        }
        return array_key_exists($permission, $this->tmhiPermissions);
    }

	public function hasWikiAccess() {
        return $this->hasPermission(self::WIKI_ACCESS);
    }
}
