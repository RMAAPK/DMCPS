import * as fs from 'fs/promises';
import * as path from 'path';
import * as os from 'os';

describe('Security Config - getDirectorySettings', () => {
    let testConfigPath: string;
    let getDirectorySettings: (p: string) => Promise<any>;

    beforeAll(async () => {
        testConfigPath = path.join(os.tmpdir(), 'test_allowed_dirs.json');
        process.env.CONFIG_PATH = testConfigPath;
        
        await fs.writeFile(testConfigPath, JSON.stringify({
            directorySettings: [
                { path: path.resolve('/projects/allowed1'), allowWrite: true, enableBackups: true },
                { path: path.resolve('/projects/allowed2'), allowWrite: false, enableBackups: false }
            ]
        }));

        const configModule = await import('../dist/config.js');
        getDirectorySettings = configModule.getDirectorySettings;
    });

    afterAll(async () => {
        try { await fs.unlink(testConfigPath); } catch (e) {}
    });

    it('should allow exact match of allowed directory', async () => {
        const settings = await getDirectorySettings('/projects/allowed1');
        expect(settings).not.toBeNull();
        expect(settings.allowWrite).toBe(true);
    });

    it('should allow nested path inside allowed directory', async () => {
        const settings = await getDirectorySettings('/projects/allowed1/subfolder/file.txt');
        expect(settings).not.toBeNull();
        expect(settings.enableBackups).toBe(true);
    });

    it('should DENY path outside allowed directory', async () => {
        const settings = await getDirectorySettings('/projects/forbidden');
        expect(settings).toBeNull();
    });

    it('should DENY path traversal attempts (e.g. ../)', async () => {
        const settings = await getDirectorySettings('/projects/allowed1/../../etc/passwd');
        expect(settings).toBeNull();
    });
    
    it('should DENY path suffix attacks', async () => {
        const settings = await getDirectorySettings('/projects/allowed1_hacked');
        expect(settings).toBeNull();
    });
});
