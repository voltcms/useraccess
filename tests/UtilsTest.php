<?php

use \PHPUnit\Framework\TestCase;
use \VoltCMS\UserAccess\Utils;
use \VoltCMS\UserAccess\SessionAuth;

class UtilsTest extends TestCase
{

    public function testAccessStatusConstantsAreDistinct()
    {
        $values = [
            Utils::ACCESS_STATUS_EVERYONE,
            Utils::ACCESS_STATUS_LOGGED_IN,
            Utils::ACCESS_STATUS_LOGGED_IN_MEMBER_OF_GROUP,
            Utils::ACCESS_STATUS_LOGGED_IN_NOT_MEMBER_OF_GROUP,
        ];
        // Regression guard: the "member of group" and "not member of group"
        // states must not collapse to the same value or access control breaks.
        $this->assertCount(4, array_unique($values));
        $this->assertNotEquals(
            Utils::ACCESS_STATUS_LOGGED_IN_MEMBER_OF_GROUP,
            Utils::ACCESS_STATUS_LOGGED_IN_NOT_MEMBER_OF_GROUP
        );
    }

    public function testContentVisibleForNotMemberOfGroup()
    {
        // A logged-in user who is NOT a member of the given group should see
        // content gated on the "not member of group" status.
        $sessionAuth = $this->createStub(SessionAuth::class);
        $sessionAuth->method('isLoggedIn')->willReturn(true);
        $sessionAuth->method('isMemberOfGroup')->willReturn(false);

        $this->assertTrue(Utils::isContentVisible(
            $sessionAuth,
            Utils::ACCESS_STATUS_LOGGED_IN_NOT_MEMBER_OF_GROUP,
            '',
            'secret-group'
        ));
    }

    public function testGetBooleanAcceptsTruthyStringsInAnyCasing()
    {
        // Regression guard: this used to compare against the literal 'True'
        // only, so a lowercase 'true' from a config file read as false and
        // silently disabled protectPage()'s redirect flags.
        foreach (['true', 'True', 'TRUE', 'tRuE', ' true ', 'yes', 'YES', 'on', '1'] as $value) {
            $this->assertTrue(Utils::getBoolean($value), 'expected true for ' . var_export($value, true));
        }
    }

    public function testGetBooleanRejectsEverythingElse()
    {
        foreach (['false', 'False', 'no', 'off', '0', '', 'maybe', 'truthy', null, [], 0, 2, 1.0] as $value) {
            $this->assertFalse(Utils::getBoolean($value), 'expected false for ' . var_export($value, true));
        }
    }

    public function testGetBooleanPassesRealBooleansThrough()
    {
        $this->assertTrue(Utils::getBoolean(true));
        $this->assertFalse(Utils::getBoolean(false));
        $this->assertTrue(Utils::getBoolean(1));
    }

    public function testContentHiddenForMemberWhenNotMemberRequired()
    {
        // A logged-in user who IS a member of the group must be denied content
        // that requires "not member of group".
        $sessionAuth = $this->createStub(SessionAuth::class);
        $sessionAuth->method('isLoggedIn')->willReturn(true);
        $sessionAuth->method('isMemberOfGroup')->willReturn(true);

        $this->assertFalse(Utils::isContentVisible(
            $sessionAuth,
            Utils::ACCESS_STATUS_LOGGED_IN_NOT_MEMBER_OF_GROUP,
            '',
            'secret-group'
        ));
    }

}
