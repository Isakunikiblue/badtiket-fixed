<?php

namespace App\Http\Controllers;

use App\Services\GoogleSheetService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\RateLimiter;

class GasBridgeController extends Controller
{
    protected GoogleSheetService $sheetService;
    protected const PASSWORD_SALT = 'MATA_SALT_2026_#@TelkomAkurasi!';

    public function __construct(GoogleSheetService $sheetService)
    {
        $this->sheetService = $sheetService;
    }

    /**
     * Dispatcher RPC serbaguna untuk bridge google.script.run dengan Otorisasi Sisi-Server (Server-Side Guard)
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
                // ==================== AUTENTIKASI & SESI ====================
                case 'validateLogin':
                case 'loginUser':
                    $u = $params['username'] ?? ($params['args_array'][0] ?? '');
                    $p = $params['password'] ?? ($params['args_array'][1] ?? '');
                    return response()->json($this->validateLogin($request, $u, $p));

                case 'logout':
                case 'logoutUser':
                    session()->forget('mata_user');
                    session()->flush();
                    return response()->json(['success' => true]);

                case 'checkSession':
                case 'getSessionUser':
                    $sUser = session('mata_user');
                    return response()->json([
                        'success' => !empty($sUser),
                        'user' => $sUser,
                    ]);

                // ==================== MANAJEMEN AKUN (SUPERADMIN ONLY) ====================
                case 'getUsers':
                case 'getAllUsers':
                    if ($denied = $this->requireAuth()) return $denied;
                    return response()->json($this->getUsers());

                case 'addUser':
                    if ($denied = $this->requireSuperadmin()) return $denied;
                    $uName = $params['username'] ?? ($params['args_array'][1] ?? '');
                    $uPass = $params['password'] ?? ($params['args_array'][2] ?? '');
                    $uRole = $params['role'] ?? ($params['args_array'][3] ?? 'user');
                    $uNama = $params['nama'] ?? ($params['args_array'][4] ?? '');
                    return response()->json($this->addUser($uName, $uPass, $uRole, $uNama));

                case 'updateUser':
                    if ($denied = $this->requireSuperadmin()) return $denied;
                    $uName = $params['username'] ?? ($params['args_array'][1] ?? '');
                    $uPass = $params['password'] ?? ($params['args_array'][2] ?? '');
                    $uRole = $params['role'] ?? ($params['args_array'][3] ?? 'user');
                    $uNama = $params['nama'] ?? ($params['args_array'][4] ?? '');
                    return response()->json($this->updateUser($uName, $uPass, $uRole, $uNama));

                case 'deleteUser':
                    if ($denied = $this->requireSuperadmin()) return $denied;
                    $uName = $params['username'] ?? ($params['args_array'][1] ?? '');
                    return response()->json($this->deleteUser($uName));

                // ==================== PERMOHONAN AKSES ====================
                case 'requestAccess':
                    $csdm = $params['namaLengkap'] ?? $params['csdm'] ?? ($params['args_array'][0] ?? '');
                    $nama = $params['username'] ?? $params['nama'] ?? ($params['args_array'][1] ?? '');
                    $pass = $params['password'] ?? ($params['args_array'][2] ?? '');
                    return response()->json($this->requestAccess($csdm, $nama, $pass));

                case 'getPendingRequests':
                    if ($denied = $this->requireSuperadmin()) return $denied;
                    return response()->json($this->getPendingRequests());

                case 'approveRequest':
                    if ($denied = $this->requireSuperadmin()) return $denied;
                    $id = $params['id'] ?? ($params['args_array'][1] ?? '');
                    return response()->json($this->approveRequest($id));

                case 'rejectRequest':
                    if ($denied = $this->requireSuperadmin()) return $denied;
                    $id = $params['id'] ?? ($params['args_array'][1] ?? '');
                    return response()->json($this->rejectRequest($id));

                // ==================== LOG AKTIVITAS & AUDIT ====================
                case 'logActivity':
                    $sUser = session('mata_user');
                    $uName = $sUser['username'] ?? ($params['username'] ?? ($params['args_array'][0] ?? 'guest'));
                    $uRole = $sUser['role'] ?? ($params['role'] ?? ($params['args_array'][1] ?? 'user'));
                    $act = $params['activity'] ?? ($params['args_array'][2] ?? '');
                    return response()->json($this->logActivity($uName, $uRole, $act));

                case 'getActivityLogs':
                case 'exportActivityLogs':
                    if ($denied = $this->requireSuperadmin()) return $denied;
                    return response()->json($this->getActivityLogs());

                // ==================== PENGATURAN SISTEM ====================
                case 'getColumnVisibilitySettings':
                    return response()->json($this->getColumnVisibilitySettings());

                case 'setColumnVisibilitySettings':
                    if ($denied = $this->requireSuperadmin()) return $denied;
                    $hDetil = filter_var($params['hideDetil'] ?? ($params['args_array'][1] ?? false), FILTER_VALIDATE_BOOLEAN);
                    $hNotes = filter_var($params['hideNotes'] ?? ($params['args_array'][2] ?? false), FILTER_VALIDATE_BOOLEAN);
                    return response()->json($this->setColumnVisibilitySettings($hDetil, $hNotes));

                case 'getDashboardData':
                    if ($denied = $this->requireAuth()) return $denied;
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
                'error' => 'Terjadi kesalahan sistem internal: ' . $e->getMessage(),
            ], 500);
        }
    }

    /**
     * Otorisasi ketat: hanya Superadmin yang boleh lanjut
     */
    protected function requireSuperadmin(): ?JsonResponse
    {
        $sessionUser = session('mata_user');
        if (!$sessionUser || ($sessionUser['role'] ?? '') !== 'superadmin') {
            return response()->json([
                'success' => false,
                'error' => 'Akses ditolak: Operasi ini membutuhkan hak akses Superadmin yang sah.',
            ], 403);
        }
        return null;
    }

    /**
     * Otorisasi dasar: Pengguna wajib login terlebih dahulu
     */
    protected function requireAuth(): ?JsonResponse
    {
        $sessionUser = session('mata_user');
        if (!$sessionUser) {
            return response()->json([
                'success' => false,
                'error' => 'Akses ditolak: Silakan login terlebih dahulu untuk melanjutkan.',
            ], 401);
        }
        return null;
    }

    /**
     * Hash password satu arah (SHA-256 + Salt MATA)
     */
    protected function hashPassword(string $password): string
    {
        if ($password === '') {
            return '';
        }
        return hash('sha256', $password . self::PASSWORD_SALT);
    }

    /**
     * Path file JSON penyimpanan data akun lokal
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
     * Ambil akun-akun terdaftar dari Google Apps Script / Spreadsheet tanpa mengekspos kredensial
     */
    protected function fetchUsersFromGoogle(): array
    {
        $webAppUrl = config('services.google_sheets.webapp_url');
        $googleUsers = [];

        if (!empty($webAppUrl)) {
            try {
                $res = Http::timeout(10)
                    ->withOptions(['allow_redirects' => true])
                    ->get($webAppUrl, ['action' => 'getUsers']);

                if ($res->successful()) {
                    $json = $res->json();
                    $raw = $json['users'] ?? (is_array($json) && isset($json[0]['username']) ? $json : []);
                    foreach ($raw as $u) {
                        if (!empty($u['username'])) {
                            $googleUsers[] = [
                                'username' => trim($u['username']),
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

        return $googleUsers;
    }

    /**
     * Ambil daftar user dari penyimpanan lokal
     */
    protected function loadUsers(bool $forceGoogleSync = false): array
    {
        $file = $this->getUsersFilePath();
        $cachedUsers = [];

        if (File::exists($file)) {
            $cachedUsers = json_decode(File::get($file), true) ?: [];
        }

        if ($forceGoogleSync || empty($cachedUsers)) {
            $googleUsers = $this->fetchUsersFromGoogle();
            if (!empty($googleUsers)) {
                $userMap = [];
                foreach ($cachedUsers as $u) {
                    $userMap[strtolower($u['username'])] = $u;
                }
                foreach ($googleUsers as $gu) {
                    $key = strtolower($gu['username']);
                    $existing = $userMap[$key] ?? [];
                    // Pertahankan password hash yang sudah tersimpan
                    $userMap[$key] = array_merge($existing, [
                        'username' => $gu['username'],
                        'role' => $gu['role'],
                        'status' => $gu['status'],
                        'nama' => $gu['nama'],
                        'password' => $existing['password'] ?? '',
                    ]);
                }
                $merged = array_values($userMap);
                $this->saveUsers($merged);
                return $merged;
            }
        }

        if (!empty($cachedUsers)) {
            return $cachedUsers;
        }

        // Akun bawaan sistem MATA (Hanya menyimpan Hash, TANPA plaintext)
        $defaultUsers = [
            [
                'username' => 'superadmin',
                'password' => $this->hashPassword('password123'),
                'role' => 'superadmin',
                'status' => 'aktif',
                'nama' => 'Superadmin',
            ],
            [
                'username' => 'badtiket',
                'password' => $this->hashPassword('badtiket@2026'),
                'role' => 'user',
                'status' => 'aktif',
                'nama' => 'Viewer',
            ],
        ];

        $this->saveUsers($defaultUsers);
        return $defaultUsers;
    }

    /**
     * Simpan daftar user ke file JSON secara aman tanpa plaintext
     */
    protected function saveUsers(array $users): void
    {
        try {
            $cleanUsers = array_map(function ($u) {
                unset($u['plain']); // Pastikan atribut plaintext dihapus total
                return $u;
            }, $users);

            $file = $this->getUsersFilePath();
            File::put($file, json_encode($cleanUsers, JSON_PRETTY_PRINT));
        } catch (\Throwable $e) {
            Log::warning('Gagal menyimpan file users: ' . $e->getMessage());
        }
    }

    /**
     * Validasi kredensial login dengan Anti-Brute-Force Rate Limiting dan Server-Side Session
     */
    protected function validateLogin(Request $request, string $username, string $password): array
    {
        $u = strtolower(trim($username));
        $p = trim($password);

        if ($u === '' || $p === '') {
            return ['success' => false, 'error' => 'Username dan Password wajib diisi.'];
        }

        // Toleransi typo umum: "superaadmin" -> "superadmin"
        if ($u === 'superaadmin') {
            $u = 'superadmin';
        }

        // 1. Anti-Brute-Force Rate Limiting (Maksimal 5 percobaan gagal per 5 menit per IP/Username)
        $throttleKey = 'mata_login:' . $request->ip() . ':' . $u;
        if (RateLimiter::tooManyAttempts($throttleKey, 5)) {
            $seconds = RateLimiter::availableIn($throttleKey);
            return [
                'success' => false,
                'rate_limited' => true,
                'error' => "Terlalu banyak percobaan login gagal. Mohon tunggu {$seconds} detik sebelum mencoba kembali.",
            ];
        }

        $webAppUrl = config('services.google_sheets.webapp_url');
        $found = null;

        // 2. Prioritas verifikasi langsung ke Google Apps Script Web App
        if (!empty($webAppUrl)) {
            try {
                $res = Http::timeout(10)
                    ->withOptions(['allow_redirects' => true])
                    ->get($webAppUrl, [
                        'action' => 'validateLogin',
                        'username' => $u,
                        'password' => $p,
                    ]);

                if ($res->successful()) {
                    $remoteJson = $res->json();
                    if ($remoteJson && ($remoteJson['success'] ?? false)) {
                        RateLimiter::clear($throttleKey);

                        $sessionData = [
                            'username' => $remoteJson['username'] ?? $u,
                            'role' => strtolower($remoteJson['role'] ?? 'user') === 'superadmin' ? 'superadmin' : 'user',
                            'nama' => $remoteJson['nama'] ?? ($remoteJson['username'] ?? $u),
                            'login_at' => now()->toIso8601String(),
                        ];
                        session(['mata_user' => $sessionData]);
                        session()->save();

                        return [
                            'success' => true,
                            'username' => $sessionData['username'],
                            'role' => $sessionData['role'],
                            'nama' => $sessionData['nama'],
                        ];
                    } elseif ($remoteJson && ($remoteJson['pending'] ?? false)) {
                        return ['success' => false, 'pending' => true];
                    }
                }
            } catch (\Throwable $e) {
                Log::info('Remote validateLogin failed, testing local store: ' . $e->getMessage());
            }
        }

        // 3. Fallback: Verifikasi terhadap Local Store
        $users = $this->loadUsers();
        foreach ($users as $usr) {
            if (strtolower(trim($usr['username'])) === $u) {
                $found = $usr;
                break;
            }
        }

        if (!$found) {
            RateLimiter::hit($throttleKey, 300);
            return ['success' => false];
        }

        if (($found['status'] ?? 'aktif') === 'pending') {
            return ['success' => false, 'pending' => true];
        }

        $hashedInput = $this->hashPassword($p);
        $storedHash = $found['password'] ?? '';

        $isValid = ($storedHash !== '' && hash_equals($storedHash, $hashedInput));

        if (!$isValid) {
            RateLimiter::hit($throttleKey, 300);
            return ['success' => false];
        }

        RateLimiter::clear($throttleKey);

        $sessionData = [
            'username' => $found['username'],
            'role' => strtolower($found['role'] ?? 'user') === 'superadmin' ? 'superadmin' : 'user',
            'nama' => $found['nama'] ?? $found['username'],
            'login_at' => now()->toIso8601String(),
        ];
        session(['mata_user' => $sessionData]);
        session()->save();

        return [
            'success' => true,
            'username' => $sessionData['username'],
            'role' => $sessionData['role'],
            'nama' => $sessionData['nama'],
        ];
    }

    /**
     * Ambil semua user untuk panel Superadmin (Hanya mengembalikan data aman tanpa password)
     */
    protected function getUsers(): array
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
    protected function addUser(string $username, string $password, string $role, string $nama): array
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
    protected function updateUser(string $username, string $password, string $role, string $nama): array
    {
        $users = $this->loadUsers();
        $found = false;

        foreach ($users as &$u) {
            if (strtolower($u['username']) === strtolower(trim($username))) {
                if (!empty($password)) {
                    $u['password'] = $this->hashPassword($password);
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
    protected function deleteUser(string $username): array
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
     * Request Akses baru dari halaman Login (Tersimpan sebagai pending)
     */
    protected function requestAccess(string $csdm, string $nama, string $password): array
    {
        $users = $this->loadUsers();
        $uName = trim($csdm);

        if ($uName === '' || $password === '') {
            return ['success' => false, 'error' => 'CSDM dan Password wajib diisi.'];
        }

        foreach ($users as $u) {
            if (strtolower($u['username']) === strtolower($uName)) {
                return ['success' => false, 'error' => 'CSDM/Username sudah terdaftar atau menunggu persetujuan.'];
            }
        }

        $users[] = [
            'username' => $uName,
            'password' => $this->hashPassword($password),
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
    protected function approveRequest(string $id): array
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
    protected function rejectRequest(string $id): array
    {
        return $this->deleteUser($id);
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
    protected function getActivityLogs(): array
    {
        $file = storage_path('app/mata_activity.json');
        $logs = [];
        if (File::exists($file)) {
            $logs = json_decode(File::get($file), true) ?: [];
        }

        return ['success' => true, 'logs' => array_reverse($logs)];
    }

    /**
     * Ambil pengaturan visibilitas kolom
     */
    protected function getColumnVisibilitySettings(): array
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
    protected function setColumnVisibilitySettings(bool $hideDetil, bool $hideNotes): array
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
