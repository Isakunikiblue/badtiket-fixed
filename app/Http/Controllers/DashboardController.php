<?php

namespace App\Http\Controllers;

use App\Services\GoogleSheetService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\View\View;

class DashboardController extends Controller
{
    protected GoogleSheetService $sheetService;

    public function __construct(GoogleSheetService $sheetService)
    {
        $this->sheetService = $sheetService;
    }

    /**
     * Halaman Utama Dashboard MATA
     */
    public function index(): View
    {
        $sessionUser = session('mata_user');

        return view('dashboard', [
            'dashboardData' => null,
            'sourceType' => 'google_apps_script_api',
            'cachedAt' => now()->toDateTimeString(),
            'currentUser' => $sessionUser,
        ]);
    }

    /**
     * Endpoint Sinkronisasi Data Manual (Bypass Cache) - Memerlukan Sesi Login Aktif
     */
    public function syncData(Request $request): JsonResponse
    {
        if (!session()->has('mata_user')) {
            return response()->json([
                'success' => false,
                'error' => 'Akses ditolak: Sesi login diperlukan untuk sinkronisasi dataset.',
            ], 401);
        }

        $freshData = $this->sheetService->getDashboardData(forceRefresh: true);

        return response()->json([
            'success' => true,
            'message' => 'Data berhasil disinkronkan langsung dari Google Spreadsheet!',
            'cached_at' => $freshData['cached_at'] ?? now()->toDateTimeString(),
            'total_fixed' => count($freshData['fixed']['rawRecords'] ?? []),
            'total_mobile' => count($freshData['mobile']['rawRecords'] ?? []),
            'data' => $freshData,
        ]);
    }

    /**
     * Endpoint API JSON data untuk client-side (dengan Proteksi Autentikasi Sisi-Server & Kompresi Gzip)
     */
    public function getData(Request $request)
    {
        if (!session()->has('mata_user')) {
            return response()->json([
                'success' => false,
                'error' => 'Akses ditolak: Sesi login diperlukan untuk mengakses dataset.',
            ], 401);
        }

        $data = $this->sheetService->getDashboardData();
        $json = json_encode($data);

        if (str_contains($request->header('Accept-Encoding', ''), 'gzip') && function_exists('gzencode')) {
            return response(gzencode($json, 6), 200, [
                'Content-Type' => 'application/json',
                'Content-Encoding' => 'gzip',
                'Cache-Control' => 'private, no-cache, no-store, must-revalidate',
            ]);
        }

        return response($json, 200, [
            'Content-Type' => 'application/json',
            'Cache-Control' => 'private, no-cache, no-store, must-revalidate',
        ]);
    }
}
