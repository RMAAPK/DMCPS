import test from 'node:test';
import assert from 'node:assert/strict';
import * as path from 'path';
import { getDirectorySettings, saveConfig } from '../dist/config.js';

test('Security Config: getDirectorySettings validates whitelist and flags', async () => {
    // Configure in-memory directory settings
    await saveConfig({
        apiKey: 'test_token_123',
        directorySettings: [
            { path: path.resolve('/tmp/allowed_test_1'), allowWrite: true, enableBackups: true },
            { path: path.resolve('/tmp/allowed_test_2'), allowWrite: false, enableBackups: false }
        ]
    });

    // 1. Exact match allowed
    const exact = await getDirectorySettings('/tmp/allowed_test_1');
    assert.notEqual(exact, null);
    assert.equal(exact?.allowWrite, true);
    assert.equal(exact?.enableBackups, true);

    // 2. Nested path allowed
    const nested = await getDirectorySettings('/tmp/allowed_test_1/nested/file.txt');
    assert.notEqual(nested, null);
    assert.equal(nested?.allowWrite, true);

    // 3. Read-only path
    const readOnly = await getDirectorySettings('/tmp/allowed_test_2');
    assert.notEqual(readOnly, null);
    assert.equal(readOnly?.allowWrite, false);

    // 4. Forbidden path outside whitelist
    const forbidden = await getDirectorySettings('/etc/shadow');
    assert.equal(forbidden, null);

    // 5. Directory traversal attempt
    const traversal = await getDirectorySettings('/tmp/allowed_test_1/../../etc/passwd');
    assert.equal(traversal, null);

    // 6. Suffix attack attempt
    const suffix = await getDirectorySettings('/tmp/allowed_test_1_hacked');
    assert.equal(suffix, null);
});
