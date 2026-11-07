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
     * Data dimuat secara asinkron (client-side fetch) agar halaman awal memuat secara instan (<50ms)
     * dan ukuran respons HTML tetap ringan (~1.4MB), jauh di bawah batas 4.5MB Vercel Serverless.
     */
    public function index(): View
    {
        return view('dashboard', [
            'dashboardData' => null,
            'sourceType' => 'google_apps_script_api',
            'cachedAt' => now()->toDateTimeString(),
        ]);
    }

    /**
     * Endpoint Sinkronisasi Data Manual (Bypass Cache)
     */
    public function syncData(): JsonResponse
    {
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
     * Endpoint API JSON data untuk client-side
     */
    public function getData(): JsonResponse
    {
        $data = $this->sheetService->getDashboardData();

        return response()->json($data);
    }
}
