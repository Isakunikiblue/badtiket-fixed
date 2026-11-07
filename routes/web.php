<?php

use App\Http\Controllers\DashboardController;
use Illuminate\Support\Facades\Route;

Route::get('/', function () {
    return redirect()->route('dashboard');
});

Route::get('/dashboard', [DashboardController::class, 'index'])->name('dashboard');
Route::post('/api/sync-data', [DashboardController::class, 'syncData'])->name('api.sync');
Route::get('/api/dashboard-data', [DashboardController::class, 'getData'])->name('api.data');
