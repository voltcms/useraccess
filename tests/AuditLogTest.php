<?php

use \PHPUnit\Framework\TestCase;
use \VoltCMS\UserAccess\AuditLog;

class AuditLogTest extends TestCase
{
    private $dir;

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . '/ua_audit_test_' . uniqid();
    }

    protected function tearDown(): void
    {
        if (is_dir($this->dir)) {
            foreach (glob($this->dir . '/*') as $f) {
                @unlink($f);
            }
            @rmdir($this->dir);
        }
    }

    public function testDisabledWhenNoDirectory()
    {
        $log = new AuditLog();
        $this->assertFalse($log->isEnabled());
        // Must be a no-op and not throw.
        $log->record(['action' => 'user.create']);
        $this->assertNull($log->getFile());
    }

    public function testRecordsJsonLineWithAutomaticTimestamp()
    {
        $log = new AuditLog($this->dir);
        $this->assertTrue($log->isEnabled());

        $log->record([
            'actor' => 'admin',
            'action' => 'user.create',
            'targetType' => 'User',
            'targetId' => 'abc',
            'target' => 'jdoe',
            'outcome' => 'success',
        ]);

        $contents = file_get_contents($log->getFile());
        $lines = array_values(array_filter(explode("\n", $contents)));
        $this->assertCount(1, $lines);

        $entry = json_decode($lines[0], true);
        $this->assertSame('admin', $entry['actor']);
        $this->assertSame('user.create', $entry['action']);
        $this->assertSame('jdoe', $entry['target']);
        $this->assertArrayHasKey('time', $entry);
        // time is ISO-8601 and parseable.
        $this->assertNotFalse(strtotime($entry['time']));
    }

    public function testAppendsMultipleEntries()
    {
        $log = new AuditLog($this->dir);
        $log->record(['action' => 'user.create', 'target' => 'a']);
        $log->record(['action' => 'user.delete', 'target' => 'a']);

        $lines = array_values(array_filter(explode("\n", file_get_contents($log->getFile()))));
        $this->assertCount(2, $lines);
        $this->assertSame('user.create', json_decode($lines[0], true)['action']);
        $this->assertSame('user.delete', json_decode($lines[1], true)['action']);
    }

    public function testProvidedTimeIsNotOverwritten()
    {
        $log = new AuditLog($this->dir);
        $log->record(['time' => '2020-01-01T00:00:00+00:00', 'action' => 'x']);
        $entry = json_decode(trim(file_get_contents($log->getFile())), true);
        $this->assertSame('2020-01-01T00:00:00+00:00', $entry['time']);
    }

    public function testDropsDenyAllHtaccessInLogDirectory()
    {
        $log = new AuditLog($this->dir);
        $log->record(['action' => 'x']);
        $this->assertFileExists($this->dir . '/.htaccess');
    }
}
