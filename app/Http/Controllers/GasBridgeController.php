<?php

namespace App\Http\Controllers;

use App\Services\GoogleSheetService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Log;

class GasBridgeController extends Controller
{
    protected GoogleSheetService $sheetService;
    protected const PASSWORD_SALT = 'MATA_SALT_2026_#@TelkomAkurasi!';

    public function __construct(GoogleSheetService $sheetService)
    {
        $this->sheetService = $sheetService;
    }

    /**
     * Dispatcher RPC serbaguna untuk bridge google.script.run
     */
    public function handleRpc(Request $request): JsonResponse
    {
        $action = $request->input('action') ?? $request->query('action', '');
        $params = $request->all();

        // Decode JSON arguments jika dikirim sebagai array args
        if (isset($params['args']) && is_string($params['args'])) {
            $decodedArgs = json_decode($params['args'], true);
            if (is_array($decodedArgs)) {
                $params['args_array'] = $decodedArgs;
            }
        }

        try {
            switch ($action) {
                case 'validateLogin':
                case 'loginUser':
                    $u = $params['username'] ?? ($params['args_array'][0] ?? '');
                    $p = $params['password'] ?? ($params['args_array'][1] ?? '');
                    return response()->json($this->validateLogin($u, $p));

                case 'getUsers':
                case 'getAllUsers':
                    $reqUser = $params['requesterUsername'] ?? ($params['args_array'][0] ?? 'superadmin');
                    return response()->json($this->getUsers($reqUser));

                case 'addUser':
                    $cUser = $params['currentUser'] ?? ($params['args_array'][0] ?? '');
                    $uName = $params['username'] ?? ($params['args_array'][1] ?? '');
                    $uPass = $params['password'] ?? ($params['args_array'][2] ?? '');
                    $uRole = $params['role'] ?? ($params['args_array'][3] ?? 'user');
                    $uNama = $params['nama'] ?? ($params['args_array'][4] ?? '');
                    return response()->json($this->addUser($cUser, $uName, $uPass, $uRole, $uNama));

                case 'updateUser':
                    $cUser = $params['currentUser'] ?? ($params['args_array'][0] ?? '');
                    $uName = $params['username'] ?? ($params['args_array'][1] ?? '');
                    $uPass = $params['password'] ?? ($params['args_array'][2] ?? '');
                    $uRole = $params['role'] ?? ($params['args_array'][3] ?? 'user');
                    $uNama = $params['nama'] ?? ($params['args_array'][4] ?? '');
                    return response()->json($this->updateUser($cUser, $uName, $uPass, $uRole, $uNama));

                case 'deleteUser':
                    $cUser = $params['currentUser'] ?? ($params['args_array'][0] ?? '');
                    $uName = $params['username'] ?? ($params['args_array'][1] ?? '');
                    return response()->json($this->deleteUser($cUser, $uName));

                case 'requestAccess':
                    $csdm = $params['namaLengkap'] ?? $params['csdm'] ?? ($params['args_array'][0] ?? '');
                    $nama = $params['username'] ?? $params['nama'] ?? ($params['args_array'][1] ?? '');
                    $pass = $params['password'] ?? ($params['args_array'][2] ?? '');
                    return response()->json($this->requestAccess($csdm, $nama, $pass));

                case 'getPendingRequests':
                    return response()->json($this->getPendingRequests());

                case 'approveRequest':
                    $cUser = $params['currentUser'] ?? ($params['args_array'][0] ?? 'superadmin');
                    $id = $params['id'] ?? ($params['args_array'][1] ?? '');
                    return response()->json($this->approveRequest($cUser, $id));

                case 'rejectRequest':
                    $cUser = $params['currentUser'] ?? ($params['args_array'][0] ?? 'superadmin');
                    $id = $params['id'] ?? ($params['args_array'][1] ?? '');
                    return response()->json($this->rejectRequest($cUser, $id));

                case 'logActivity':
                    $uName = $params['username'] ?? ($params['args_array'][0] ?? '');
                    $uRole = $params['role'] ?? ($params['args_array'][1] ?? 'user');
                    $act = $params['activity'] ?? ($params['args_array'][2] ?? '');
                    return response()->json($this->logActivity($uName, $uRole, $act));

                case 'getActivityLogs':
                    $reqUser = $params['requesterUsername'] ?? ($params['args_array'][0] ?? 'superadmin');
                    return response()->json($this->getActivityLogs($reqUser));

                case 'exportActivityLogs':
                    $reqUser = $params['requesterUsername'] ?? ($params['args_array'][0] ?? 'superadmin');
                    return response()->json($this->exportActivityLogs($reqUser));

                case 'getColumnVisibilitySettings':
                    $uName = $params['username'] ?? ($params['args_array'][0] ?? '');
                    return response()->json($this->getColumnVisibilitySettings($uName));

                case 'setColumnVisibilitySettings':
                    $uName = $params['username'] ?? ($params['args_array'][0] ?? '');
                    $hDetil = filter_var($params['hideDetil'] ?? ($params['args_array'][1] ?? false), FILTER_VALIDATE_BOOLEAN);
                    $hNotes = filter_var($params['hideNotes'] ?? ($params['args_array'][2] ?? false), FILTER_VALIDATE_BOOLEAN);
                    return response()->json($this->setColumnVisibilitySettings($uName, $hDetil, $hNotes));

                case 'getDashboardData':
                    return response()->json($this->sheetService->getDashboardData());

                default:
                    return response()->json([
                        'success' => true,
                        'message' => 'Action received: ' . $action,
                    ]);
            }
        } catch (\Throwable $e) {
            Log::error('GasBridgeController error on action ' . $action . ': ' . $e->getMessage());
            return response()->json([
                'success' => false,
                'error' => $e->getMessage(),
            ], 500);
        }
    }

    /**
     * Hash password sesuai algoritma Code.gs (SHA-256 + Salt MATA)
     */
    protected function hashPassword(string $password): string
    {
        if ($password === '') {
            return '';
        }
        return hash('sha256', $password . self::PASSWORD_SALT);
    }

    /**
     * Path file JSON penyimpanan data akun
     */
    protected function getUsersFilePath(): string
    {
        $dir = storage_path('app');
        if (!is_dir($dir)) {
            @mkdir($dir, 0777, true);
        }
        return $dir . '/mata_users.json';
    }

    /**
     * Ambil akun-akun terdaftar langsung dari Google Spreadsheet / Google Apps Script
     */
    protected function fetchUsersFromGoogle(): array
    {
        $webAppUrl = config('services.google_sheets.webapp_url');
        $sheetId = config('services.google_sheets.spreadsheet_id');
        $googleUsers = [];

        // 1. Coba ambil dari Google Apps Script Web App (?action=getUsers)
        if (!empty($webAppUrl)) {
            try {
                $res = \Illuminate\Support\Facades\Http::timeout(10)
                    ->withOptions(['allow_redirects' => true])
                    ->get($webAppUrl, ['action' => 'getUsers']);

                if ($res->successful()) {
                    $json = $res->json();
                    $raw = $json['users'] ?? (is_array($json) && isset($json[0]['username']) ? $json : []);
                    foreach ($raw as $u) {
                        if (!empty($u['username'])) {
                            $googleUsers[] = [
                                'username' => trim($u['username']),
                                'password' => $u['password'] ?? '',
                                'plain' => $u['plain'] ?? $u['password'] ?? '',
                                'role' => strtolower($u['role'] ?? 'user') === 'superadmin' ? 'superadmin' : 'user',
                                'status' => strtolower($u['status'] ?? 'aktif') === 'pending' ? 'pending' : 'aktif',
                                'nama' => $u['nama'] ?? $u['username'],
                            ];
                        }
                    }
                }
            } catch (\Throwable $e) {
                Log::info('Fetch users from Google Apps Script: ' . $e->getMessage());
            }
        }

        // 2. Coba ambil dari Google Spreadsheet ID (tab sheet "Users") via CSV
        if (empty($googleUsers) && !empty($sheetId)) {
            try {
                $url = "https://docs.google.com/spreadsheets/d/{$sheetId}/gviz/tq?tqx=out:csv&sheet=" . urlencode('Users');
                $res = \Illuminate\Support\Facades\Http::timeout(10)->get($url);

                if ($res->successful()) {
                    $lines = explode("\n", trim($res->body()));
                    // Lewati baris header (index 0)
                    for ($i = 1; $i < count($lines); $i++) {
                        $row = str_getcsv($lines[$i]);
                        $uName = trim($row[0] ?? '');
                        if ($uName !== '') {
                            $googleUsers[] = [
                                'username' => $uName,
                                'password' => trim($row[1] ?? ''),
                                'plain' => trim($row[1] ?? ''),
                                'role' => strtolower(trim($row[2] ?? 'user')) === 'superadmin' ? 'superadmin' : 'user',
                                'status' => strtolower(trim($row[3] ?? 'aktif')) === 'pending' ? 'pending' : 'aktif',
                                'nama' => trim($row[4] ?? '') ?: $uName,
                            ];
                        }
                    }
                }
            } catch (\Throwable $e) {
                Log::info('Fetch users from Google Sheet CSV: ' . $e->getMessage());
            }
        }

        return $googleUsers;
    }

    /**
     * Ambil daftar user dari JSON store (dengan sinkronisasi otomatis ke Google Spreadsheet)
     */
    protected function loadUsers(bool $forceGoogleSync = false): array
    {
        $file = $this->getUsersFilePath();
        $cachedUsers = [];

        if (File::exists($file)) {
            $cachedUsers = json_decode(File::get($file), true) ?: [];
        }

        // Jika dipaksa sync atau cache lokal masih kosong, ambil dari Google Sheet
        if ($forceGoogleSync || empty($cachedUsers)) {
            $googleUsers = $this->fetchUsersFromGoogle();
            if (!empty($googleUsers)) {
                $userMap = [];
                foreach ($cachedUsers as $u) {
                    $userMap[strtolower($u['username'])] = $u;
                }
                foreach ($googleUsers as $gu) {
                    $key = strtolower($gu['username']);
                    $userMap[$key] = array_merge($userMap[$key] ?? [], $gu);
                }
                $merged = array_values($userMap);
                $this->saveUsers($merged);
                return $merged;
            }
        }

        if (!empty($cachedUsers)) {
            return $cachedUsers;
        }

        // Akun bawaan sistem MATA
        $defaultUsers = [
            [
                'username' => 'superadmin',
                'password' => $this->hashPassword('password123'),
                'plain' => 'password123',
                'role' => 'superadmin',
                'status' => 'aktif',
                'nama' => 'Superadmin',
            ],
            [
                'username' => 'badtiket',
                'password' => $this->hashPassword('badtiket@2026'),
                'plain' => 'badtiket@2026',
                'role' => 'user',
                'status' => 'aktif',
                'nama' => 'Viewer',
            ],
        ];

        $this->saveUsers($defaultUsers);
        return $defaultUsers;
    }

    /**
     * Simpan daftar user ke file JSON
     */
    protected function saveUsers(array $users): void
    {
        try {
            $file = $this->getUsersFilePath();
            File::put($file, json_encode($users, JSON_PRETTY_PRINT));
        } catch (\Throwable $e) {
            Log::warning('Gagal menyimpan file users: ' . $e->getMessage());
        }
    }

    /**
     * Validasi kredensial login (mendukung password ter-hash maupun plain, auto-sync Google Sheet)
     */
    protected function validateLogin(string $username, string $password): array
    {
        $u = strtolower(trim($username));
        $p = trim($password);

        if ($u === '' || $p === '') {
            return ['success' => false];
        }

        // Toleransi typo umum: "superaadmin" -> "superadmin"
        if ($u === 'superaadmin') {
            $u = 'superadmin';
        }

        $users = $this->loadUsers();
        $found = null;

        foreach ($users as $usr) {
            if (strtolower(trim($usr['username'])) === $u) {
                $found = $usr;
                break;
            }
        }

        // Jika user tidak ditemukan di cache lokal, sync langsung dari Google Sheet!
        if (!$found) {
            $freshUsers = $this->loadUsers(forceGoogleSync: true);
            foreach ($freshUsers as $usr) {
                if (strtolower(trim($usr['username'])) === $u) {
                    $found = $usr;
                    break;
                }
            }
        }

        if (!$found) {
            return ['success' => false];
        }

        if (($found['status'] ?? 'aktif') === 'pending') {
            return ['success' => false, 'pending' => true];
        }

        $hashedInput = $this->hashPassword($p);
        $storedHash = $found['password'] ?? '';
        $storedPlain = $found['plain'] ?? '';

        $isValid = ($storedHash !== '' && hash_equals($storedHash, $hashedInput))
            || ($storedPlain !== '' && $storedPlain === $p)
            || ($storedHash !== '' && $storedHash === $p);

        if (!$isValid) {
            return ['success' => false];
        }

        return [
            'success' => true,
            'username' => $found['username'],
            'role' => strtolower($found['role'] ?? 'user') === 'superadmin' ? 'superadmin' : 'user',
            'nama' => $found['nama'] ?? $found['username'],
        ];
    }

    /**
     * Ambil semua user untuk panel Superadmin (otomatis sync dari Google Sheet)
     */
    protected function getUsers(string $requesterUsername): array
    {
        $users = $this->loadUsers(forceGoogleSync: true);
        $safeUsers = array_map(function ($u) {
            return [
                'username' => $u['username'],
                'role' => $u['role'] ?? 'user',
                'status' => $u['status'] ?? 'aktif',
                'nama' => $u['nama'] ?? $u['username'],
            ];
        }, $users);

        return ['success' => true, 'users' => $safeUsers];
    }

    /**
     * Tambah akun baru oleh Superadmin
     */
    protected function addUser(string $cUser, string $username, string $password, string $role, string $nama): array
    {
        $users = $this->loadUsers();
        $uName = trim($username);

        foreach ($users as $u) {
            if (strtolower($u['username']) === strtolower($uName)) {
                return ['success' => false, 'error' => 'Username sudah digunakan.'];
            }
        }

        $users[] = [
            'username' => $uName,
            'password' => $this->hashPassword($password),
            'plain' => $password,
            'role' => strtolower($role) === 'superadmin' ? 'superadmin' : 'user',
            'status' => 'aktif',
            'nama' => trim($nama) ?: $uName,
        ];

        $this->saveUsers($users);
        return ['success' => true];
    }

    /**
     * Update akun oleh Superadmin
     */
    protected function updateUser(string $cUser, string $username, string $password, string $role, string $nama): array
    {
        $users = $this->loadUsers();
        $found = false;

        foreach ($users as &$u) {
            if (strtolower($u['username']) === strtolower(trim($username))) {
                if (!empty($password)) {
                    $u['password'] = $this->hashPassword($password);
                    $u['plain'] = $password;
                }
                $u['role'] = strtolower($role) === 'superadmin' ? 'superadmin' : 'user';
                if (!empty($nama)) {
                    $u['nama'] = trim($nama);
                }
                $found = true;
                break;
            }
        }

        if ($found) {
            $this->saveUsers($users);
            return ['success' => true];
        }

        return ['success' => false, 'error' => 'User tidak ditemukan.'];
    }

    /**
     * Hapus akun
     */
    protected function deleteUser(string $cUser, string $username): array
    {
        if (strtolower(trim($username)) === 'superadmin') {
            return ['success' => false, 'error' => 'Akun superadmin utama tidak dapat dihapus.'];
        }

        $users = $this->loadUsers();
        $filtered = array_filter($users, fn ($u) => strtolower($u['username']) !== strtolower(trim($username)));

        $this->saveUsers(array_values($filtered));
        return ['success' => true];
    }

    /**
     * Request Akses baru dari halaman Login
     */
    protected function requestAccess(string $csdm, string $nama, string $password): array
    {
        $users = $this->loadUsers();
        $uName = trim($csdm);

        foreach ($users as $u) {
            if (strtolower($u['username']) === strtolower($uName)) {
                return ['success' => false, 'error' => 'CSDM/Username sudah terdaftar atau menunggu persetujuan.'];
            }
        }

        $users[] = [
            'username' => $uName,
            'password' => $this->hashPassword($password),
            'plain' => $password,
            'role' => 'user',
            'status' => 'pending',
            'nama' => trim($nama) ?: $uName,
        ];

        $this->saveUsers($users);
        return ['success' => true];
    }

    /**
     * Ambil permohonan akses yang masih pending
     */
    protected function getPendingRequests(): array
    {
        $users = $this->loadUsers();
        $pending = array_filter($users, fn ($u) => ($u['status'] ?? '') === 'pending');

        $requests = array_map(function ($u) {
            return [
                'id' => $u['username'],
                'csdm' => $u['username'],
                'nama' => $u['nama'] ?? $u['username'],
                'role' => $u['role'] ?? 'user',
                'status' => 'pending',
            ];
        }, array_values($pending));

        return ['success' => true, 'requests' => $requests];
    }

    /**
     * Setujui permohonan akses
     */
    protected function approveRequest(string $cUser, string $id): array
    {
        $users = $this->loadUsers();
        $found = false;

        foreach ($users as &$u) {
            if (strtolower($u['username']) === strtolower(trim($id))) {
                $u['status'] = 'aktif';
                $found = true;
                break;
            }
        }

        if ($found) {
            $this->saveUsers($users);
            return ['success' => true];
        }

        return ['success' => false, 'error' => 'Permintaan tidak ditemukan.'];
    }

    /**
     * Tolak permohonan akses
     */
    protected function rejectRequest(string $cUser, string $id): array
    {
        return $this->deleteUser($cUser, $id);
    }

    /**
     * Log aktivitas pengguna
     */
    protected function logActivity(string $username, string $role, string $activity): array
    {
        $file = storage_path('app/mata_activity.json');
        $logs = [];
        if (File::exists($file)) {
            $logs = json_decode(File::get($file), true) ?: [];
        }

        $logs[] = [
            'timestamp' => now()->timezone('Asia/Jakarta')->format('d/m/Y H:i:s') . ' WIB',
            'username' => $username,
            'role' => $role,
            'activity' => $activity,
        ];

        // Simpan maksimal 300 aktivitas terakhir
        if (count($logs) > 300) {
            $logs = array_slice($logs, -300);
        }

        try {
            File::put($file, json_encode($logs));
        } catch (\Throwable $e) {}

        return ['success' => true];
    }

    /**
     * Ambil riwayat log aktivitas
     */
    protected function getActivityLogs(string $requesterUsername): array
    {
        $file = storage_path('app/mata_activity.json');
        $logs = [];
        if (File::exists($file)) {
            $logs = json_decode(File::get($file), true) ?: [];
        }

        return ['success' => true, 'logs' => array_reverse($logs)];
    }

    /**
     * Export log aktivitas
     */
    protected function exportActivityLogs(string $requesterUsername): array
    {
        return $this->getActivityLogs($requesterUsername);
    }

    /**
     * Ambil pengaturan visibilitas kolom
     */
    protected function getColumnVisibilitySettings(string $username): array
    {
        $file = storage_path('app/mata_settings.json');
        $settings = ['hideDetilForUser' => false, 'hideNotesForUser' => false];
        if (File::exists($file)) {
            $saved = json_decode(File::get($file), true);
            if (is_array($saved)) {
                $settings = array_merge($settings, $saved);
            }
        }
        return array_merge(['success' => true], $settings);
    }

    /**
     * Simpan pengaturan visibilitas kolom
     */
    protected function setColumnVisibilitySettings(string $username, bool $hideDetil, bool $hideNotes): array
    {
        $file = storage_path('app/mata_settings.json');
        $settings = [
            'hideDetilForUser' => $hideDetil,
            'hideNotesForUser' => $hideNotes,
        ];
        try {
            File::put($file, json_encode($settings));
        } catch (\Throwable $e) {}

        return ['success' => true];
    }
}

