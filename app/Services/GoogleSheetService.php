<?php

namespace App\Services;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

class GoogleSheetService
{
    /**
     * Cache TTL in seconds (default 3 minutes = 180s)
     */
    protected int $cacheTtl;

    public function __construct()
    {
        $this->cacheTtl = (int) config('services.google_sheets.cache_ttl', 180);
    }

    /**
     * Mendapatkan data gabungan Fixed dan Mobile dengan Smart Caching
     */
    public function getDashboardData(bool $forceRefresh = false): array
    {
        $cacheKey = 'mata_dashboard_dataset_v1';

        if ($forceRefresh) {
            Cache::forget($cacheKey);
        }

        return Cache::remember($cacheKey, $this->cacheTtl, function () {
            return $this->fetchFromSource();
        });
    }

    /**
     * Clear Cache secara manual
     */
    public function clearCache(): void
    {
        Cache::forget('mata_dashboard_dataset_v1');
    }

    /**
     * Ambil data dari sumber (Web App URL, CSV Export, atau Mock Data lokal)
     */
    protected function fetchFromSource(): array
    {
        $webAppUrl = config('services.google_sheets.webapp_url');
        $sheetId = config('services.google_sheets.spreadsheet_id');

        // 1. Jika Web App URL Google Apps Script diatur
        if (!empty($webAppUrl)) {
            try {
                $response = Http::timeout(60)
                    ->withOptions(['allow_redirects' => true])
                    ->get($webAppUrl, ['action' => 'getDashboardData']);

                if ($response->successful()) {
                    $json = $response->json();
                    if (!empty($json) && (isset($json['fixed']) || isset($json['rawRecords']))) {
                        $fixedRecords = $json['fixed']['rawRecords'] ?? $json['rawRecords'] ?? [];
                        $fixedFilters = $json['fixed']['filters'] ?? $json['filters'] ?? [];
                        $mobileRecords = $json['mobile']['rawRecords'] ?? [];
                        $mobileFilters = $json['mobile']['filters'] ?? [];

                        return [
                            'rawRecords' => $fixedRecords,
                            'filters' => $fixedFilters,
                            'fixed' => [
                                'rawRecords' => $fixedRecords,
                                'filters' => $fixedFilters,
                            ],
                            'mobile' => [
                                'rawRecords' => $mobileRecords,
                                'filters' => $mobileFilters,
                            ],
                            'source_type' => 'google_apps_script_api',
                            'cached_at' => now()->toDateTimeString(),
                        ];
                    }
                }
            } catch (\Throwable $e) {
                Log::warning('Gagal fetch dari Google Apps Script Web App: ' . $e->getMessage());
            }
        }

        // 2. Jika Google Spreadsheet ID diatur (fetch via CSV export)
        if (!empty($sheetId)) {
            try {
                $fixedRecords = $this->fetchSheetCsv($sheetId, 'Data');
                $mobileRecords = $this->fetchSheetCsv($sheetId, 'Data2');

                if (!empty($fixedRecords) || !empty($mobileRecords)) {
                    $fixedProcessed = $this->processRecords($fixedRecords);
                    $mobileProcessed = $this->processRecords($mobileRecords);

                    return [
                        'rawRecords' => $fixedProcessed['records'],
                        'filters' => $fixedProcessed['filters'],
                        'fixed' => [
                            'rawRecords' => $fixedProcessed['records'],
                            'filters' => $fixedProcessed['filters'],
                        ],
                        'mobile' => [
                            'rawRecords' => $mobileProcessed['records'],
                            'filters' => $mobileProcessed['filters'],
                        ],
                        'source_type' => 'google_sheets_csv',
                        'cached_at' => now()->toDateTimeString(),
                    ];
                }
            } catch (\Throwable $e) {
                Log::warning('Gagal fetch dari Google Spreadsheet CSV: ' . $e->getMessage());
            }
        }

        // 3. Fallback: Data Sample/Mockup Lokal (Aman untuk pengujian awal)
        return $this->getMockData();
    }

    /**
     * Fetch Google Spreadsheet per sheet sebagai CSV
     */
    protected function fetchSheetCsv(string $sheetId, string $sheetName): array
    {
        $url = "https://docs.google.com/spreadsheets/d/{$sheetId}/gviz/tq?tqx=out:csv&sheet=" . urlencode($sheetName);
        $res = Http::timeout(20)->get($url);

        if (!$res->successful()) {
            return [];
        }

        $lines = explode("\n", trim($res->body()));
        if (count($lines) < 2) {
            return [];
        }

        $records = [];
        // Lewati baris 0 (header)
        for ($i = 1; $i < count($lines); $i++) {
            $row = str_getcsv($lines[$i]);
            if (empty($row)) continue;
            // Pastikan baris memiliki data minimal Incident / Agent Name
            if (!empty($row[4]) || !empty($row[6])) {
                // Pad baris ke 16 kolom
                $row = array_pad($row, 16, '');
                // Masking catatan Kolom N
                if (!empty($row[13])) {
                    $row[13] = $this->maskNotes($row[13]);
                }
                $records[] = $row;
            }
        }

        return $records;
    }

    /**
     * Memproses baris mentah menjadi struktur data dan opsi filter unik
     */
    protected function processRecords(array $records): array
    {
        $setTanggal = [];
        $setBulan = [];
        $setTahun = [];
        $setUnit = [];
        $setKategoriL = [];
        $setSourceBy = [];

        foreach ($records as &$row) {
            if (!empty($row[0])) $setTanggal[$row[0]] = true;
            if (!empty($row[1])) $setBulan[$row[1]] = true;
            if (!empty($row[2])) $setTahun[$row[2]] = true;
            if (!empty($row[9])) $setUnit[$row[9]] = true;
            if (!empty($row[11])) $setKategoriL[$row[11]] = true;
            if (!empty($row[15])) $setSourceBy[$row[15]] = true;
        }

        $sortNum = function($arr) {
            $keys = array_keys($arr);
            sort($keys, SORT_NATURAL);
            return $keys;
        };

        return [
            'records' => $records,
            'filters' => [
                'tanggal' => $sortNum($setTanggal),
                'bulan' => array_keys($setBulan),
                'tahun' => array_keys($setTahun),
                'unit' => $sortNum($setUnit),
                'kategoriL' => array_keys($setKategoriL),
                'sourceBy' => array_keys($setSourceBy),
            ]
        ];
    }

    /**
     * Sensor Masking untuk nomor identitas pelanggan di kolom catatan (Notes by Solver)
     */
    public function maskNotes(string $text): string
    {
        return preg_replace('/(\b(?:\+?62|08|02\d|KM\d*)\d{4,8})(\d{4,5}\b)/i', '$1*****', $text);
    }

    /**
     * Mockup data dual-domain Fixed & Mobile untuk development lokal yang cepat
     */
    protected function getMockData(): array
    {
        $months = ['JANUARI', 'FEBRUARI', 'MARET', 'APRIL', 'MEI', 'JUNI', 'JULI', 'AGUSTUS', 'SEPTEMBER', 'OKTOBER'];
        $unitsFixed = ['CC BANDUNG', 'CC SEMARANG', 'ECARE BANDUNG', 'ECARE SEMARANG'];
        $unitsMobile = ['CC MOBILE BDG', 'CC MOBILE SMG', 'DIGITAL CARE MOBILE'];

        $categoriesFixed = [
            'MANDATORY TICKET',
            'KIP TIDAK SESUAI',
            'CASE TIDAK PERLU DIESKALASI',
            'PENGGUNAAN NOMER DUMMY',
            'DOUBLE TICKET',
            'SALAH TUJUAN'
        ];

        $categoriesMobile = [
            'CASE ID DI CREATE DENGAN KIP YANG TIDAK SESUAI DENGAN PANDUAN SOLUSI',
            'CASE TIDAK PERLU DIESKALASI',
            'DOUBLE TICKET',
            'KIP TIDAK SESUAI',
            'KIP/SYMPTOMP TIDAK SESUAI',
            'MANDATORY TICKET',
            'PENGGUNAAN NOMER DUMMY',
            'SALAH TUJUAN',
            'SALAH TUJUAN ESKALASI',
            'ISL',
            'OSL'
        ];

        $tls = [
            ['name' => "AMANATUN NAFI'AH", 'spv' => "RISA EKA MARLANGEN"],
            ['name' => "AGUNG DWI CAHYO", 'spv' => "RISA EKA MARLANGEN"],
            ['name' => "DWI NUR HIDAYATULLOH", 'spv' => "RISA EKA MARLANGEN"],
            ['name' => "ILYAS AFANDI", 'spv' => "ARGI BINTANG"],
            ['name' => "RAKA AWALI", 'spv' => "AAN YANUAR"],
            ['name' => "ADHY SULISTRIYANTO", 'spv' => "ERWIN SENATRYA"]
        ];

        // Fixed records
        $rawRecordsFixed = [];
        for ($i = 0; $i < 450; $i++) {
            $tgl = (string)(($i % 28) + 1);
            $bln = ($i % 2 === 0) ? 'OKTOBER' : 'SEPTEMBER';
            $tlObj = $tls[$i % count($tls)];
            $unit = $unitsFixed[$i % count($unitsFixed)];
            $cat = $categoriesFixed[$i % count($categoriesFixed)];
            $isSgh = ($i % 9 === 0);

            $rawRecordsFixed[] = [
                $tgl, $bln, '2026', '2026-10-01',
                'TKT-FIX-' . (1000 + $i),
                'SIAD' . (200 + ($i % 15)),
                'AGENT ' . str_pad($i % 30 + 1, 2, '0', STR_PAD_LEFT) . ' - PRATAMA',
                $tlObj['name'],
                $tlObj['spv'],
                $unit,
                'K31 - Tidak Bisa Browsing - 1P / 3P Mati Total',
                $cat,
                'Sub Detail Fixed',
                'Pelanggan 0812345***** lapor kendala',
                $isSgh ? 'SANGGAHAN DITERIMA' : 'RESOLVED',
                'PORTAL'
            ];
        }

        // Mobile records
        $rawRecordsMobile = [];
        for ($i = 0; $i < 320; $i++) {
            $tgl = (string)(($i % 28) + 1);
            $bln = ($i % 2 === 0) ? 'OKTOBER' : 'SEPTEMBER';
            $tlObj = $tls[$i % count($tls)];
            $unit = $unitsMobile[$i % count($unitsMobile)];
            $cat = $categoriesMobile[$i % count($categoriesMobile)];
            $isSgh = ($i % 8 === 0);

            $rawRecordsMobile[] = [
                $tgl, $bln, '2026', '2026-10-01',
                'TKT-MOB-' . (5000 + $i),
                'SIAD-M' . (300 + ($i % 12)),
                'AGENT MOB ' . str_pad($i % 25 + 1, 2, '0', STR_PAD_LEFT) . ' - SANTOSO',
                $tlObj['name'],
                $tlObj['spv'],
                $unit,
                'KIP-MOB-01 Paket Data Tidak Aktif',
                $cat,
                'Sub Detail Mobile',
                'Pelanggan 0813268***** kendala kuota',
                $isSgh ? 'SANGGAHAN DITERIMA' : 'RESOLVED',
                'MYTELKOMSEL'
            ];
        }

        $fixedProc = $this->processRecords($rawRecordsFixed);
        $mobileProc = $this->processRecords($rawRecordsMobile);

        return [
            'rawRecords' => $fixedProc['records'],
            'filters' => $fixedProc['filters'],
            'fixed' => [
                'rawRecords' => $fixedProc['records'],
                'filters' => $fixedProc['filters'],
            ],
            'mobile' => [
                'rawRecords' => $mobileProc['records'],
                'filters' => $mobileProc['filters'],
            ],
            'source_type' => 'mock_offline_dataset',
            'cached_at' => now()->toDateTimeString(),
        ];
    }
}

