<?php

namespace App\Http\Controllers;

use App\Services\GoogleSheetService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Crypt;
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
     * dan Proteksi Anti-CSRF ketat.
     */
    public function handleRpc(Request $request): JsonResponse
    {
        // 1. Validasi Keamanan Origin / Referer (Anti-CSRF)
        if ($csrfDenied = $this->validateCsrfOrigin($request)) {
            return $csrfDenied;
        }

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
                    if ($methodDenied = $this->requirePostMethod($request)) return $methodDenied;
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

                // ==================== MANAJEMEN AKUN (SUPERADMIN ONLY & POST ONLY) ====================
                case 'getUsers':
                case 'getAllUsers':
                    if ($denied = $this->requireAuth()) return $denied;
                    return response()->json($this->getUsers());

                case 'addUser':
                    if ($methodDenied = $this->requirePostMethod($request)) return $methodDenied;
                    if ($denied = $this->requireSuperadmin()) return $denied;
                    $uName = $params['username'] ?? ($params['args_array'][1] ?? '');
                    $uPass = $params['password'] ?? ($params['args_array'][2] ?? '');
                    $uRole = $params['role'] ?? ($params['args_array'][3] ?? 'user');
                    $uNama = $params['nama'] ?? ($params['args_array'][4] ?? '');
                    return response()->json($this->addUser($uName, $uPass, $uRole, $uNama));

                case 'updateUser':
                    if ($methodDenied = $this->requirePostMethod($request)) return $methodDenied;
                    if ($denied = $this->requireSuperadmin()) return $denied;
                    $uName = $params['username'] ?? ($params['args_array'][1] ?? '');
                    $uPass = $params['password'] ?? ($params['args_array'][2] ?? '');
                    $uRole = $params['role'] ?? ($params['args_array'][3] ?? 'user');
                    $uNama = $params['nama'] ?? ($params['args_array'][4] ?? '');
                    return response()->json($this->updateUser($uName, $uPass, $uRole, $uNama));

                case 'deleteUser':
                    if ($methodDenied = $this->requirePostMethod($request)) return $methodDenied;
                    if ($denied = $this->requireSuperadmin()) return $denied;
                    $uName = $params['username'] ?? ($params['args_array'][1] ?? '');
                    return response()->json($this->deleteUser($uName));

                // ==================== PERMOHONAN AKSES (POST ONLY) ====================
                case 'requestAccess':
                    if ($methodDenied = $this->requirePostMethod($request)) return $methodDenied;
                    $csdm = $params['namaLengkap'] ?? $params['csdm'] ?? ($params['args_array'][0] ?? '');
                    $nama = $params['username'] ?? $params['nama'] ?? ($params['args_array'][1] ?? '');
                    $pass = $params['password'] ?? ($params['args_array'][2] ?? '');
                    return response()->json($this->requestAccess($csdm, $nama, $pass));

                case 'getPendingRequests':
                    if ($denied = $this->requireSuperadmin()) return $denied;
                    return response()->json($this->getPendingRequests());

                case 'approveRequest':
                    if ($methodDenied = $this->requirePostMethod($request)) return $methodDenied;
                    if ($denied = $this->requireSuperadmin()) return $denied;
                    $id = $params['id'] ?? ($params['args_array'][1] ?? '');
                    return response()->json($this->approveRequest($id));

                case 'rejectRequest':
                    if ($methodDenied = $this->requirePostMethod($request)) return $methodDenied;
                    if ($denied = $this->requireSuperadmin()) return $denied;
                    $id = $params['id'] ?? ($params['args_array'][1] ?? '');
                    return response()->json($this->rejectRequest($id));

                // ==================== LOG AKTIVITAS & AUDIT ====================
                case 'logActivity':
                    $sUser = session('mata_user');
                    $uName = !empty($params['username']) ? $params['username'] : ($sUser['username'] ?? ($params['args_array'][0] ?? 'guest'));
                    $uRole = !empty($params['role']) ? $params['role'] : ($sUser['role'] ?? ($params['args_array'][1] ?? 'user'));
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
                    if ($methodDenied = $this->requirePostMethod($request)) return $methodDenied;
                    if ($denied = $this->requireSuperadmin()) return $denied;
                    $hDetil = filter_var($params['hideDetil'] ?? ($params['args_array'][1] ?? false), FILTER_VALIDATE_BOOLEAN);
                    $hNotes = filter_var($params['hideNotes'] ?? ($params['args_array'][2] ?? false), FILTER_VALIDATE_BOOLEAN);
                    return response()->json($this->setColumnVisibilitySettings($hDetil, $hNotes));

                // ==================== NOTIFIKASI TELEGRAM ====================
                case 'sendTelegramReport':
                    if ($methodDenied = $this->requirePostMethod($request)) return $methodDenied;
                    if ($denied = $this->requireSuperadmin()) return $denied;
                    return response()->json($this->sendTelegramMtdReport());

                case 'testTelegram':
                    if ($methodDenied = $this->requirePostMethod($request)) return $methodDenied;
                    if ($denied = $this->requireSuperadmin()) return $denied;
                    return response()->json($this->testTelegram());

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
            $errorMsg = config('app.debug') ? $e->getMessage() : 'Terjadi kesalahan sistem internal. Silakan hubungi administrator.';
            return response()->json([
                'success' => false,
                'error' => $errorMsg,
            ], 500);
        }
    }

    /**
     * Validasi Keamanan Asal Permintaan (CSRF Origin & Referer Verification)
     */
    protected function validateCsrfOrigin(Request $request): ?JsonResponse
    {
        if ($request->isMethod('POST')) {
            $origin = $request->header('Origin');
            $referer = $request->header('Referer');
            $host = $request->getHost();

            if ($origin && !str_contains(strtolower($origin), strtolower($host))) {
                return response()->json([
                    'success' => false,
                    'error' => 'Permintaan ditolak: Pelanggaran keamanan lintas-domain (CSRF Origin Mismatch).',
                ], 403);
            }

            if ($referer && !str_contains(strtolower($referer), strtolower($host))) {
                return response()->json([
                    'success' => false,
                    'error' => 'Permintaan ditolak: Pelanggaran keamanan referer (CSRF Referer Mismatch).',
                ], 403);
            }
        }
        return null;
    }

    /**
     * Wajibkan metode POST untuk seluruh operasi pengubahan data (Anti-CSRF GET Exploits)
     */
    protected function requirePostMethod(Request $request): ?JsonResponse
    {
        if (!$request->isMethod('POST')) {
            return response()->json([
                'success' => false,
                'error' => 'Metode HTTP ' . $request->method() . ' tidak diizinkan untuk operasi perubahan data ini. Wajib menggunakan POST.',
            ], 405);
        }
        return null;
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
     * Path file penyimpanan data akun lokal
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
     * Simpan file JSON ke disk dengan Enkripsi AES-256 (Data Encryption at Rest)
     */
    protected function saveEncryptedJson(string $filePath, array $data): void
    {
        try {
            $dir = dirname($filePath);
            if (!is_dir($dir)) {
                @mkdir($dir, 0777, true);
            }
            $json = json_encode($data, JSON_PRETTY_PRINT);
            $encrypted = Crypt::encryptString($json);
            File::put($filePath, $encrypted);
        } catch (\Throwable $e) {
            Log::warning("Gagal menyimpan encrypted file {$filePath}: " . $e->getMessage());
        }
    }

    /**
     * Baca file JSON terenkripsi dari disk dengan toleransi format legacy
     */
    protected function loadEncryptedJson(string $filePath): array
    {
        if (!File::exists($filePath)) {
            return [];
        }

        try {
            $content = File::get($filePath);
            try {
                $decrypted = Crypt::decryptString($content);
                return json_decode($decrypted, true) ?: [];
            } catch (\Throwable $eDec) {
                // Fallback otomatis jika data sebelumnya masih format JSON plain -> enkripsikan sekarang
                $plain = json_decode($content, true);
                if (is_array($plain)) {
                    $this->saveEncryptedJson($filePath, $plain);
                    return $plain;
                }
            }
        } catch (\Throwable $e) {
            Log::warning("Gagal membaca file {$filePath}: " . $e->getMessage());
        }

        return [];
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
     * Ambil daftar user dari penyimpanan lokal (Terenkripsi AES-256)
     */
    protected function loadUsers(bool $forceGoogleSync = false): array
    {
        $file = $this->getUsersFilePath();
        $cachedUsers = $this->loadEncryptedJson($file);

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
     * Simpan daftar user ke file terenkripsi secara aman tanpa plaintext
     */
    protected function saveUsers(array $users): void
    {
        $cleanUsers = array_map(function ($u) {
            unset($u['plain']); // Pastikan atribut plaintext dihapus total
            return $u;
        }, $users);

        $file = $this->getUsersFilePath();
        $this->saveEncryptedJson($file, $cleanUsers);
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
     * Log aktivitas pengguna (Terenkripsi AES-256)
     */
    protected function logActivity(string $username, string $role, string $activity): array
    {
        $uName = trim($username);
        // Akun superadmin sengaja tidak dicatat ke log aktivitas
        if (strtolower($uName) === 'superadmin') {
            return ['success' => true, 'ignored' => true];
        }

        // 1. Simpan ke storage terenkripsi lokal
        $file = storage_path('app/mata_activity.json');
        $logs = $this->loadEncryptedJson($file);

        $logs[] = [
            'timestamp' => now()->timezone('Asia/Jakarta')->format('d/m/Y H:i:s') . ' WIB',
            'username' => $uName,
            'role' => $role,
            'activity' => $activity,
        ];

        if (count($logs) > 300) {
            $logs = array_slice($logs, -300);
        }

        $this->saveEncryptedJson($file, $logs);

        // 2. Forward ke Google Apps Script (agar tercatat permanen di sheet ActivityLog Google Spreadsheet)
        $webAppUrl = config('services.google_sheets.webapp_url');
        if (!empty($webAppUrl)) {
            try {
                Http::timeout(5)->withOptions(['allow_redirects' => true])->get($webAppUrl, [
                    'action' => 'logActivity',
                    'username' => $uName,
                    'role' => $role,
                    'activity' => $activity,
                ]);
            } catch (\Throwable $e) {
                Log::warning('Gagal forward logActivity ke GAS: ' . $e->getMessage());
            }
        }

        return ['success' => true];
    }

    /**
     * Ambil riwayat log aktivitas (Mendekripsi data aman)
     */
    protected function getActivityLogs(): array
    {
        // 1. Coba ambil riwayat dari Google Apps Script (sheet ActivityLog di Google Spreadsheet)
        $webAppUrl = config('services.google_sheets.webapp_url');
        if (!empty($webAppUrl)) {
            try {
                $res = Http::timeout(10)->withOptions(['allow_redirects' => true])->get($webAppUrl, [
                    'action' => 'getActivityLogs',
                    'requester' => 'superadmin',
                ]);
                if ($res->successful()) {
                    $json = $res->json();
                    if (!empty($json) && isset($json['success']) && $json['success'] && isset($json['logs']) && is_array($json['logs'])) {
                        $cleanLogs = array_filter($json['logs'], function ($l) {
                            return strtolower(trim($l['username'] ?? '')) !== 'superadmin';
                        });
                        return ['success' => true, 'logs' => array_values($cleanLogs)];
                    }
                }
            } catch (\Throwable $e) {
                Log::warning('Gagal fetch activity logs dari GAS: ' . $e->getMessage());
            }
        }

        // 2. Fallback: baca dari storage lokal
        $file = storage_path('app/mata_activity.json');
        $logs = $this->loadEncryptedJson($file);
        $cleanLogs = array_filter($logs, function ($l) {
            return strtolower(trim($l['username'] ?? '')) !== 'superadmin';
        });

        return ['success' => true, 'logs' => array_values(array_reverse($cleanLogs))];
    }

    /**
     * Ambil pengaturan visibilitas kolom (Mendekripsi data aman)
     */
    protected function getColumnVisibilitySettings(): array
    {
        $file = storage_path('app/mata_settings.json');
        $settings = ['hideDetilForUser' => false, 'hideNotesForUser' => false];
        $saved = $this->loadEncryptedJson($file);
        if (is_array($saved)) {
            $settings = array_merge($settings, $saved);
        }

        return array_merge(['success' => true], $settings);
    }

    /**
     * Simpan pengaturan visibilitas kolom (Terenkripsi AES-256)
     */
    protected function setColumnVisibilitySettings(bool $hideDetil, bool $hideNotes): array
    {
        $file = storage_path('app/mata_settings.json');
        $settings = [
            'hideDetilForUser' => $hideDetil,
            'hideNotesForUser' => $hideNotes,
        ];
        $this->saveEncryptedJson($file, $settings);

        return ['success' => true];
    }

    /**
     * Kirim pesan ke Telegram Bot
     */
    protected function sendTelegramRaw(string $text): array
    {
        $botToken = config('services.telegram.bot_token', env('TELEGRAM_BOT_TOKEN'));
        $chatId = config('services.telegram.chat_id', env('TELEGRAM_CHAT_ID'));

        if (empty($botToken) || empty($chatId)) {
            return ['success' => false, 'error' => 'Bot Token atau Chat ID Telegram belum dikonfigurasi.'];
        }

        try {
            $url = "https://api.telegram.org/bot{$botToken}/sendMessage";
            $res = Http::timeout(15)->post($url, [
                'chat_id' => $chatId,
                'text' => $text,
                'parse_mode' => 'HTML',
                'disable_web_page_preview' => true,
            ]);

            if ($res->successful()) {
                return ['success' => true, 'result' => $res->json()];
            }

            return ['success' => false, 'error' => $res->body()];
        } catch (\Throwable $e) {
            Log::error('Telegram send error: ' . $e->getMessage());
            return ['success' => false, 'error' => $e->getMessage()];
        }
    }

    /**
     * Test koneksi Telegram
     */
    protected function testTelegram(): array
    {
        $msg = "🚀 <b>Uji Coba Koneksi Telegram Sukses!</b>\n\nSistem Dashboard MATA berhasil terhubung dengan akun Telegram Anda melalui @agentmata_bot.";
        return $this->sendTelegramRaw($msg);
    }

    /**
     * Bangun dan kirim laporan Period Comparison MTD & inputan hari ini ke Telegram
     */
    protected function sendTelegramMtdReport(): array
    {
        $data = $this->sheetService->getDashboardData();
        $fixed = $data['fixed']['rawRecords'] ?? [];
        $mobile = $data['mobile']['rawRecords'] ?? [];
        $all = array_merge($fixed, $mobile);

        $now = now()->timezone('Asia/Jakarta');
        $todayDay = (int) $now->format('j');
        $todayMonthNum = (int) $now->format('n');
        $monthNames = [1 => 'JANUARI', 2 => 'FEBRUARI', 3 => 'MARET', 4 => 'APRIL', 5 => 'MEI', 6 => 'JUNI', 7 => 'JULI', 8 => 'AGUSTUS', 9 => 'SEPTEMBER', 10 => 'OKTOBER', 11 => 'NOVEMBER', 12 => 'DESEMBER'];
        $todayMonth = $monthNames[$todayMonthNum] ?? 'NOVEMBER';
        $todayYear = $now->format('Y');

        // 1. Cek inputan hari ini
        $todayFixed = 0;
        $todayMobile = 0;
        foreach ($fixed as $r) {
            $d = (int) ($r[0] ?? 0);
            $m = strtoupper(trim($r[1] ?? ''));
            $y = trim($r[2] ?? '');
            if ($d === $todayDay && $m === $todayMonth && $y === $todayYear) {
                $todayFixed++;
            }
        }
        foreach ($mobile as $r) {
            $d = (int) ($r[0] ?? 0);
            $m = strtoupper(trim($r[1] ?? ''));
            $y = trim($r[2] ?? '');
            if ($d === $todayDay && $m === $todayMonth && $y === $todayYear) {
                $todayMobile++;
            }
        }
        $totalToday = $todayFixed + $todayMobile;

        // 2. Cut-off MTD (rentang tanggal tertinggi di bulan berjalan pada dataset Fixed)
        $currMonth = $todayMonth;
        $prevMonth = $todayMonthNum > 1 ? $monthNames[$todayMonthNum - 1] : 'DESEMBER';
        $targetMtdPool = !empty($fixed) ? $fixed : $all;

        $maxDay = 0;
        foreach ($targetMtdPool as $r) {
            if (strtoupper(trim($r[1] ?? '')) === $currMonth) {
                $d = (int) ($r[0] ?? 0);
                if ($d > $maxDay) $maxDay = $d;
            }
        }
        if ($maxDay === 0) $maxDay = $todayDay;

        // Hitung MTD (Exclude Sanggahan Diterima = Net Bad Ticket)
        $isNotSgh = fn($r) => !str_contains(strtoupper($r[14] ?? ''), 'SANGGAHAN DITERIMA');

        $currMtd = [];
        $prevMtd = [];
        foreach ($targetMtdPool as $r) {
            $d = (int) ($r[0] ?? 0);
            $m = strtoupper(trim($r[1] ?? ''));
            if ($d >= 1 && $d <= $maxDay && $isNotSgh($r)) {
                if ($m === $currMonth) $currMtd[] = $r;
                elseif ($m === $prevMonth) $prevMtd[] = $r;
            }
        }

        $currCount = count($currMtd);
        $prevCount = count($prevMtd);
        $diff = $currCount - $prevCount;
        $pct = $prevCount > 0 ? round(($diff / $prevCount) * 100, 1) : 0;
        $trendIcon = $diff < 0 ? '🟢' : ($diff > 0 ? '🔴' : '🟡');
        $trendStatus = $diff < 0 ? 'TURUN' : ($diff > 0 ? 'NAIK' : 'STABIL');
        $sign = $diff > 0 ? '+' : '';

        $cShort = ucfirst(strtolower(substr($currMonth, 0, 3)));
        $pShort = ucfirst(strtolower(substr($prevMonth, 0, 3)));

        // Kategori breakdown
        $catsCurr = [];
        $catsPrev = [];
        foreach ($currMtd as $r) {
            $c = trim($r[11] ?? 'LAINNYA');
            $catsCurr[$c] = ($catsCurr[$c] ?? 0) + 1;
        }
        foreach ($prevMtd as $r) {
            $c = trim($r[11] ?? 'LAINNYA');
            $catsPrev[$c] = ($catsPrev[$c] ?? 0) + 1;
        }
        arsort($catsCurr);
        $topCats = array_slice($catsCurr, 0, 5, true);

        $catText = '';
        $i = 1;
        foreach ($topCats as $cName => $cVal) {
            $pVal = $catsPrev[$cName] ?? 0;
            $dVal = $cVal - $pVal;
            $cPct = $pVal > 0 ? round(($dVal / $pVal) * 100) : ($cVal > 0 ? 100 : 0);
            $sVal = $dVal > 0 ? "+$dVal" : "$dVal";
            $sPct = $dVal > 0 ? "+$cPct" : "$cPct";
            $cIcon = $dVal < 0 ? '🟢 Turun' : ($dVal > 0 ? '🔴 Naik' : '➖ Stabil');
            $catText .= "{$i}. <b>{$cName}</b>\n   • {$cShort}: <b>{$cVal}</b> vs {$pShort}: <b>{$pVal}</b> [{$cIcon} {$sPct}% ({$sVal})]\n";
            $i++;
        }

        // Unit breakdown
        $unitsCurr = [];
        $unitsPrev = [];
        foreach ($currMtd as $r) {
            $u = trim($r[9] ?? '');
            if ($u) $unitsCurr[$u] = ($unitsCurr[$u] ?? 0) + 1;
        }
        foreach ($prevMtd as $r) {
            $u = trim($r[9] ?? '');
            if ($u) $unitsPrev[$u] = ($unitsPrev[$u] ?? 0) + 1;
        }
        arsort($unitsCurr);
        $topUnits = array_slice($unitsCurr, 0, 5, true);

        $unitText = '';
        foreach ($topUnits as $uName => $cVal) {
            $pVal = $unitsPrev[$uName] ?? 0;
            $dVal = $cVal - $pVal;
            $uPct = $pVal > 0 ? round(($dVal / $pVal) * 100) : ($cVal > 0 ? 100 : 0);
            $sVal = $dVal > 0 ? "+$dVal" : "$dVal";
            $sPct = $dVal > 0 ? "+$uPct" : "$uPct";
            $uIcon = $dVal < 0 ? '🟢 Turun' : ($dVal > 0 ? '🔴 Naik' : '➖ Stabil');
            $unitText .= "• <b>{$uName}</b>: {$cShort} <b>{$cVal}</b> vs {$pShort} <b>{$pVal}</b> [{$uIcon} {$sPct}% ({$sVal})]\n";
        }

        $dateStr = $now->translatedFormat('l, d F Y') . ' | ' . $now->format('H:i') . ' WIB';

        $msg = "🔔 <b>LAPORAN HARIAN & PERIOD COMPARISON MATA</b>\n";
        $msg .= "📅 <b>Tanggal Cek:</b> {$dateStr}\n\n";

        $msg .= "━━━━━━━━━━━━━━━━━━━━━━━━\n";
        $msg .= "📍 <b>1. STATUS INPUTAN HARI INI ({$todayDay} {$todayMonth})</b>\n";
        $msg .= "━━━━━━━━━━━━━━━━━━━━━━━━\n";
        if ($totalToday > 0) {
            $msg .= "✅ <b>Ditemukan {$totalToday} Inputan Tiket Baru Hari Ini!</b>\n";
            $msg .= "• Fixed  : <b>{$todayFixed}</b> tiket\n";
            $msg .= "• Mobile : <b>{$todayMobile}</b> tiket\n\n";
        } else {
            $msg .= "⚠️ <i>Belum ada inputan baru untuk hari ini.</i>\n";
            $msg .= "<i>(Cut-off data inputan terakhir per tanggal {$maxDay} {$currMonth} 2026)</i>\n\n";
        }

        $msg .= "━━━━━━━━━━━━━━━━━━━━━━━━\n";
        $msg .= "📈 <b>2. PERIOD COMPARISON (MTD MoM)</b>\n";
        $msg .= "<b>Rentang Cut-Off: 1–{$maxDay} {$currMonth} vs 1–{$maxDay} {$prevMonth} 2026</b>\n";
        $msg .= "━━━━━━━━━━━━━━━━━━━━━━━━\n";
        $msg .= "• MTD Bulan Ini ({$currMonth})  : <b>{$currCount} Tiket</b>\n";
        $msg .= "• MTD Bulan Lalu ({$prevMonth}) : <b>{$prevCount} Tiket</b>\n";
        $msg .= "• Tren Evaluasi        : {$trendIcon} <b>{$trendStatus} {$sign}{$pct}% ({$sign}{$diff} Tiket)</b>\n\n";

        if ($catText) {
            $msg .= "📌 <b>Perbandingan Top Kategori Bad Ticket:</b>\n{$catText}\n";
        }
        if ($unitText) {
            $msg .= "🏢 <b>Perbandingan Per Unit:</b>\n{$unitText}\n";
        }

        $msg .= "━━━━━━━━━━━━━━━━━━━━━━━━\n";
        $msg .= "🔗 <a href=\"https://dashboard-mata.vercel.app\">Buka Dashboard MATA</a>";

        return $this->sendTelegramRaw($msg);
    }
}
