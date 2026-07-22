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
