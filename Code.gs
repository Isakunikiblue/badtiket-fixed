function doGet(e) {
  // 1. API endpoint untuk integrasi Laravel / eksternal (mengambil data JSON dari Spreadsheet)
  if (e && e.parameter) {
    const action = e.parameter.action;

    // Ambil data dashboard analitik
    if (action === 'getDashboardData' || e.parameter.format === 'json') {
      const data = getDashboardData();
      return ContentService.createTextOutput(JSON.stringify(data))
        .setMimeType(ContentService.MimeType.JSON);
    }

    // Ambil seluruh akun terdaftar dari sheet "Users" untuk sinkronisasi (Kredensial Password TIDAK pernah dikirim ke publik)
    if (action === 'getUsers' || action === 'getAllUsers') {
      const users = getUsersRaw_().map(function(u) {
        return {
          username: u.username,
          role: u.role,
          status: u.status,
          nama: u.nama
        };
      });
      return ContentService.createTextOutput(JSON.stringify({ success: true, users: users }))
        .setMimeType(ContentService.MimeType.JSON);
    }

    // Validasi login langsung dari sheet "Users"
    if (action === 'validateLogin') {
      const u = e.parameter.username || '';
      const p = e.parameter.password || '';
      const result = validateLogin(u, p);
      return ContentService.createTextOutput(JSON.stringify(result))
        .setMimeType(ContentService.MimeType.JSON);
    }

    // Trigger pengiriman laporan Telegram Harian & MTD Period Comparison
    if (action === 'sendTelegramReport') {
      const result = generateTelegramMtdReport();
      return ContentService.createTextOutput(JSON.stringify(result))
        .setMimeType(ContentService.MimeType.JSON);
    }

    // Uji coba koneksi bot Telegram
    if (action === 'testTelegram') {
      const result = testTelegramConnection();
      return ContentService.createTextOutput(JSON.stringify(result))
        .setMimeType(ContentService.MimeType.JSON);
    }
  }

  // 2. Tampilan Web App standar (tetap berjalan normal seperti biasa)
  return HtmlService.createTemplateFromFile('Index')
      .evaluate()
      .setTitle('MATA (Monitoring Akurasi Tiket & Action)')
      .addMetaTag('viewport', 'width=device-width, initial-scale=1')
      .setXFrameOptionsMode(HtmlService.XFrameOptionsMode.ALLOWALL);
}

// Helper untuk menyisipkan file HTML lain (mis. Login.html) ke dalam template Index.html
// Dipanggil dari Index.html dengan: <?!= include('Login'); ?>
function include(filename) {
  return HtmlService.createHtmlOutputFromFile(filename).getContent();
}

// ===================== SISTEM MULTI-AKUN (Sheet "Users") =====================
// Kredensial sekarang disimpan di sheet "Users" (bukan lagi Script Properties tunggal),
// supaya bisa ada banyak akun dengan role berbeda (superadmin / user).
// Kolom sheet "Users": A=Username | B=Password | C=Role (superadmin/user)
//
// Sheet ini akan DIBUAT OTOMATIS saat pertama kali dibutuhkan (validateLogin/getAllUsers/dst),
// lengkap dengan akun default:
//   - superadmin / password123   (role: superadmin, bisa tambah/edit/hapus akun)
//   - badtiket   / badtiket@2026 (role: user, akun lama supaya tidak ada yang terkunci)
//
// CATATAN KEAMANAN: password disimpan apa adanya (plain text) di sheet, konsisten dengan
// pendekatan sederhana yang sudah dipakai sejak awal proyek ini. Sheet "Users" sebaiknya
// di-restrict aksesnya (jangan di-share ke orang lain) karena berisi kredensial login.

const USERS_SHEET_NAME = 'Users';

// ===================== PASSWORD HASHING (SHA-256 + SALT) =====================
// Sesuai standar VA/Keamanan OWASP, password tidak disimpan plain text, melainkan
// di-hash secara one-way menggunakan Utilities.computeDigest SHA-256 + secret salt.
const PASSWORD_SALT = 'MATA_SALT_2026_#@TelkomAkurasi!';

function hashPassword_(password, salt) {
  if (!password) return '';
  const s = (salt !== undefined && salt !== null) ? String(salt) : PASSWORD_SALT;
  const rawBytes = Utilities.computeDigest(
    Utilities.DigestAlgorithm.SHA_256,
    password + s,
    Utilities.Charset.UTF_8
  );
  let hashStr = '';
  for (let i = 0; i < rawBytes.length; i++) {
    let byteVal = rawBytes[i];
    if (byteVal < 0) byteVal += 256;
    let hex = byteVal.toString(16);
    if (hex.length === 1) hex = '0' + hex;
    hashStr += hex;
  }
  return hashStr;
}

function isHashed_(str) {
  return typeof str === 'string' && /^[0-9a-f]{64}$/i.test(str.trim());
}

// ===================== PENGATURAN VISIBILITAS KOLOM (PERMANEN, LEVEL SISTEM) =====================
// Mengontrol apakah kolom "Detil Bad Ticket (M)" dan "Notes by Solver (N)" pada modal
// "Detail Temuan Bad Ticket" boleh dilihat oleh akun dengan role 'user'. Pengaturan ini
// disimpan di Script Properties (bukan sesi/browser), jadi PERMANEN dan berlaku untuk
// SEMUA akun role 'user' -- hanya superadmin yang boleh mengubahnya. Superadmin sendiri
// selalu bisa melihat kedua kolom ini apapun pengaturannya (supaya bisa mengelola datanya).
const COLVIS_PROP_DETIL = 'HIDE_DETIL_FOR_USER';
const COLVIS_PROP_NOTES = 'HIDE_NOTES_FOR_USER';

// Bisa dipanggil oleh SIAPA SAJA yang sudah login (bukan cuma superadmin), karena
// pengaturan ini perlu dibaca setiap kali modal detail dibuka, oleh role apapun.
function getColumnVisibilitySettings(requesterUsername) {
  try {
    const users = getUsersRaw_();
    const requester = users.find(u => u.username === String(requesterUsername || '').trim());
    if (!requester) {
      return { success: false, error: 'Akun tidak dikenali.' };
    }
    const props = PropertiesService.getScriptProperties();
    return {
      success: true,
      hideDetilForUser: props.getProperty(COLVIS_PROP_DETIL) === 'true',
      hideNotesForUser: props.getProperty(COLVIS_PROP_NOTES) === 'true'
    };
  } catch (error) {
    return { success: false, error: error.toString() };
  }
}

// HANYA superadmin yang boleh mengubah pengaturan ini
function setColumnVisibilitySettings(requesterUsername, hideDetilForUser, hideNotesForUser) {
  try {
    const users = getUsersRaw_();
    const requester = users.find(u => u.username === String(requesterUsername || '').trim());
    if (!requester || requester.role !== 'superadmin') {
      return { success: false, error: 'Akses ditolak. Hanya superadmin yang dapat mengubah pengaturan ini.' };
    }
    const props = PropertiesService.getScriptProperties();
    props.setProperty(COLVIS_PROP_DETIL, hideDetilForUser ? 'true' : 'false');
    props.setProperty(COLVIS_PROP_NOTES, hideNotesForUser ? 'true' : 'false');
    return { success: true };
  } catch (error) {
    return { success: false, error: error.toString() };
  }
}

// ===================== LOG AKTIVITAS PENGGUNA (KHUSUS DILIHAT SUPERADMIN) =====================
// Setiap login, logout, dan perpindahan halaman oleh user dicatat ke sheet "ActivityLog"
// supaya superadmin bisa melihat siapa membuka apa, dan pada tanggal & jam berapa.
const ACTIVITY_LOG_SHEET_NAME = 'ActivityLog';

function ensureActivityLogSheet_() {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  let sheet = ss.getSheetByName(ACTIVITY_LOG_SHEET_NAME);
  if (!sheet) {
    sheet = ss.insertSheet(ACTIVITY_LOG_SHEET_NAME);
    sheet.getRange(1, 1, 1, 4).setValues([['Timestamp', 'Username', 'Role', 'Aktivitas']]);
  }
  return sheet;
}

// Mencatat satu baris aktivitas. Dipanggil dari client setiap kali user login, logout,
// atau membuka halaman/menu tertentu. Sengaja dibuat "fire and forget" (client tidak perlu
// menunggu respons) supaya tidak memperlambat navigasi.
function logActivity(username, role, activity) {
  try {
    const uName = String(username || '').trim();
    // User dengan username "superadmin" TIDAK dicatat ke log aktivitas.
    // Jika user bukan superadmin (username bukan "superadmin") tapi role-nya superadmin, tetap dicatat.
    if (uName.toLowerCase() === 'superadmin') {
      return { success: true, ignored: true };
    }

    const sheet = ensureActivityLogSheet_();
    const tz = Session.getScriptTimeZone();
    const timestamp = Utilities.formatDate(new Date(), tz, "yyyy-MM-dd HH:mm:ss");
    sheet.appendRow([
      timestamp,
      uName,
      String(role || '').trim(),
      String(activity || '').trim()
    ]);
    return { success: true };
  } catch (error) {
    Logger.log("Error pada logActivity: " + error.toString());
    return { success: false, error: error.toString() };
  }
}

// Mengambil log aktivitas -- HANYA berhasil jika requesterUsername adalah superadmin.
// Dibatasi maksimal 300 baris terakhir (paling baru duluan) supaya tetap ringan di client.
function getActivityLogs(requesterUsername) {
  try {
    const users = getUsersRaw_();
    const requester = users.find(u => u.username === String(requesterUsername || '').trim());
    if (!requester || requester.role !== 'superadmin') {
      return { success: false, error: 'Akses ditolak. Hanya superadmin yang dapat melihat log aktivitas.' };
    }

    const sheet = ensureActivityLogSheet_();
    const lastRow = sheet.getLastRow();
    if (lastRow < 2) {
      return { success: true, logs: [] };
    }

    const MAX_ROWS = 300;
    const startRow = Math.max(2, lastRow - MAX_ROWS + 1);
    const numRows = lastRow - startRow + 1;
    const values = sheet.getRange(startRow, 1, numRows, 4).getValues();

    // Peta username -> nama, supaya tabel log bisa menampilkan Nama tanpa perlu ubah
    // struktur sheet ActivityLog (Nama diambil dari data akun terkini di sheet Users)
    const namaMap = {};
    users.forEach(u => { namaMap[u.username] = u.nama; });

    const tz = Session.getScriptTimeZone();
    const logs = values
      .map(r => {
        let ts = r[0];
        if (ts instanceof Date) {
          ts = Utilities.formatDate(ts, tz, "dd/MM/yyyy HH:mm:ss") + " WIB";
        } else if (ts) {
          ts = String(ts).trim();
        }
        return {
          timestamp: ts || '',
          username: String(r[1] || '').trim(),
          nama: namaMap[String(r[1] || '').trim()] || '',
          role: String(r[2] || '').trim(),
          activity: String(r[3] || '').trim()
        };
      })
      // Saring agar user dengan username "superadmin" TIDAK masuk ke log aktivitas.
      // Jika user bukan superadmin (username bukan "superadmin") tapi role-nya superadmin, tetap masuk.
      .filter(log => log.username.toLowerCase() !== 'superadmin')
      .reverse(); // paling baru tampil paling atas

    return { success: true, logs: logs };
  } catch (error) {
    return { success: false, error: error.toString() };
  }
}

function ensureUsersSheet_() {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  let sheet = ss.getSheetByName(USERS_SHEET_NAME);
  if (!sheet) {
    sheet = ss.insertSheet(USERS_SHEET_NAME);
    sheet.getRange(1, 1, 1, 5).setValues([['Username', 'Password', 'Role', 'Status', 'Nama']]);
    sheet.getRange(2, 1, 2, 5).setValues([
      ['superadmin', hashPassword_('password123'), 'superadmin', 'aktif', 'Superadmin'],
      ['badtiket', hashPassword_('badtiket@2026'), 'user', 'aktif', 'Viewer']
    ]);
  } else if (sheet.getLastRow() < 2) {
    sheet.getRange(2, 1, 2, 5).setValues([
      ['superadmin', hashPassword_('password123'), 'superadmin', 'aktif', 'Superadmin'],
      ['badtiket', hashPassword_('badtiket@2026'), 'user', 'aktif', 'Viewer']
    ]);
  } else if (sheet.getLastColumn() < 5) {
    // Sheet sudah ada tapi dibuat sebelum kolom Nama ditambahkan -> tambahkan headernya saja
    sheet.getRange(1, 5).setValue('Nama');
  }
  return sheet;
}

function getUsersRaw_() {
  const sheet = ensureUsersSheet_();
  const lastRow = sheet.getLastRow();
  if (lastRow < 2) return [];
  const values = sheet.getRange(2, 1, lastRow - 1, 5).getValues();
  return values
    .map((r, idx) => ({
      row: idx + 2,
      username: String(r[0] || '').trim(),
      password: String(r[1] || ''),
      role: String(r[2] || '').trim().toLowerCase() === 'superadmin' ? 'superadmin' : 'user',
      // Baris lama tanpa kolom Status dianggap 'aktif' (supaya akun yang sudah ada tidak mendadak terkunci)
      status: String(r[3] || '').trim().toLowerCase() === 'pending' ? 'pending' : 'aktif',
      nama: String(r[4] || '').trim()
    }))
    .filter(u => u.username !== '');
}

function validateLogin(username, password) {
  try {
    const u = String(username || '').trim();
    const p = String(password || '').trim();
    const users = getUsersRaw_();
    
    // Cari user berdasarkan username (case-insensitive)
    const found = users.find(usr => usr.username.toLowerCase() === u.toLowerCase());

    if (!found) {
      return { success: false };
    }
    if (found.status === 'pending') {
      return { success: false, pending: true };
    }

    const hashedInput = hashPassword_(p);
    let isPasswordValid = false;

    if (found.password === hashedInput) {
      isPasswordValid = true;
    } else if (found.password === p) {
      // BACKWARD COMPATIBILITY: Password di sheet masih plain text.
      // Cocok dengan plain text input, lalu OTOMATIS dimigrasikan ke SHA-256 hash!
      isPasswordValid = true;
      try {
        const sheet = ensureUsersSheet_();
        sheet.getRange(found.row, 2).setValue(hashedInput);
        Logger.log('Auto-migrasi password user ' + found.username + ' ke SHA-256 hash berhasil.');
      } catch (errMigrate) {
        Logger.log('Gagal auto-migrasi hash: ' + errMigrate.toString());
      }
    }

    if (!isPasswordValid) {
      return { success: false };
    }

    return { success: true, username: found.username, role: found.role };
  } catch (error) {
    Logger.log("Error pada validateLogin: " + error.toString());
    return { success: false, error: error.toString() };
  }
}

// Mengajukan permintaan akses baru (dari halaman Login, tombol "Request Akses").
// Akun langsung tersimpan dengan status 'pending' -- TIDAK bisa dipakai login
// sampai disetujui (approve) oleh superadmin.
// ===================== PENGATURAN VISIBILITAS KOLOM (KHUSUS ROLE "USER") =====================
// Superadmin bisa mengatur apakah kolom "Detil Bad Ticket (M)" dan "Notes by Solver (N)"
// boleh dilihat oleh akun role "User" pada modal Detail Temuan Bad Ticket.
// Pengaturan disimpan permanen di Script Properties (berlaku untuk SEMUA akun "User"),
// sedangkan superadmin sendiri SELALU bisa melihat kedua kolom tsb apapun pengaturannya.
const COLUMN_VISIBILITY_PROPS = {
  hideDetilForUser: 'HIDE_DETIL_FOR_USER',
  hideNotesForUser: 'HIDE_NOTES_FOR_USER'
};

function getColumnVisibilitySettings() {
  try {
    const props = PropertiesService.getScriptProperties();
    return {
      success: true,
      hideDetilForUser: props.getProperty(COLUMN_VISIBILITY_PROPS.hideDetilForUser) === 'true',
      hideNotesForUser: props.getProperty(COLUMN_VISIBILITY_PROPS.hideNotesForUser) === 'true'
    };
  } catch (error) {
    return { success: false, error: error.toString(), hideDetilForUser: false, hideNotesForUser: false };
  }
}

// Mengubah pengaturan -- HANYA superadmin yang boleh
function setColumnVisibilitySettings(requesterUsername, hideDetilForUser, hideNotesForUser) {
  try {
    const users = getUsersRaw_();
    const requester = users.find(u => u.username === String(requesterUsername || '').trim());
    if (!requester || requester.role !== 'superadmin') {
      return { success: false, error: 'Akses ditolak. Hanya superadmin yang dapat mengubah pengaturan ini.' };
    }
    const props = PropertiesService.getScriptProperties();
    props.setProperty(COLUMN_VISIBILITY_PROPS.hideDetilForUser, hideDetilForUser ? 'true' : 'false');
    props.setProperty(COLUMN_VISIBILITY_PROPS.hideNotesForUser, hideNotesForUser ? 'true' : 'false');
    return { success: true };
  } catch (error) {
    return { success: false, error: error.toString() };
  }
}

function requestAccess(csdm, nama, password) {
  try {
    const sheet = ensureUsersSheet_();
    const users = getUsersRaw_();

    const uName = String(csdm || '').trim();
    const uNama = String(nama || '').trim();
    const uPass = String(password || '').trim();

    if (!uName || !uNama || !uPass) {
      return { success: false, error: 'CSDM, Nama, dan Password wajib diisi.' };
    }
    if (!/^[0-9]+$/.test(uName)) {
      return { success: false, error: 'CSDM harus berupa angka saja.' };
    }
    if (users.some(u => u.username.toLowerCase() === uName.toLowerCase())) {
      return { success: false, error: 'CSDM ini sudah terdaftar atau masih menunggu persetujuan.' };
    }

    const hashedPass = hashPassword_(uPass);
    sheet.appendRow([uName, hashedPass, 'user', 'pending', uNama]);
    return { success: true };
  } catch (error) {
    return { success: false, error: error.toString() };
  }
}

// Mengambil daftar akun yang SUDAH AKTIF -- HANYA berhasil jika requesterUsername adalah superadmin
function getAllUsers(requesterUsername) {
  try {
    const users = getUsersRaw_();
    const requester = users.find(u => u.username === String(requesterUsername || '').trim());
    if (!requester || requester.role !== 'superadmin') {
      return { success: false, error: 'Akses ditolak. Hanya superadmin yang dapat mengelola akun.' };
    }
    return {
      success: true,
      users: users.filter(u => u.status === 'aktif').map(u => ({
        username: u.username,
        role: u.role,
        password: isHashed_(u.password) ? 'SHA256:' + u.password.substring(0, 8) + '...' : u.password,
        isHashed: isHashed_(u.password),
        nama: u.nama
      }))
    };
  } catch (error) {
    return { success: false, error: error.toString() };
  }
}

// Mengambil daftar permintaan akses yang masih PENDING -- khusus superadmin
function getPendingRequests(requesterUsername) {
  try {
    const users = getUsersRaw_();
    const requester = users.find(u => u.username === String(requesterUsername || '').trim());
    if (!requester || requester.role !== 'superadmin') {
      return { success: false, error: 'Akses ditolak.' };
    }
    return {
      success: true,
      requests: users.filter(u => u.status === 'pending').map(u => ({ username: u.username, nama: u.nama }))
    };
  } catch (error) {
    return { success: false, error: error.toString() };
  }
}

// Menyetujui permintaan akses -- status diubah dari 'pending' menjadi 'aktif'
function approveUser(requesterUsername, targetUsername) {
  try {
    const sheet = ensureUsersSheet_();
    const users = getUsersRaw_();
    const requester = users.find(u => u.username === String(requesterUsername || '').trim());
    if (!requester || requester.role !== 'superadmin') {
      return { success: false, error: 'Akses ditolak. Hanya superadmin yang dapat menyetujui permintaan.' };
    }
    const target = users.find(u => u.username === String(targetUsername || '').trim());
    if (!target) {
      return { success: false, error: 'Permintaan tidak ditemukan.' };
    }
    sheet.getRange(target.row, 4).setValue('aktif');
    return { success: true };
  } catch (error) {
    return { success: false, error: error.toString() };
  }
}

// Menyetujui SEMUA permintaan akses yang masih pending sekaligus, dalam satu kali panggilan
function approveAllPendingUsers(requesterUsername) {
  try {
    const sheet = ensureUsersSheet_();
    const users = getUsersRaw_();
    const requester = users.find(u => u.username === String(requesterUsername || '').trim());
    if (!requester || requester.role !== 'superadmin') {
      return { success: false, error: 'Akses ditolak. Hanya superadmin yang dapat menyetujui permintaan.' };
    }

    const pendingUsers = users.filter(u => u.status === 'pending');
    if (pendingUsers.length === 0) {
      return { success: false, error: 'Tidak ada permintaan yang menunggu persetujuan.' };
    }

    pendingUsers.forEach(u => {
      sheet.getRange(u.row, 4).setValue('aktif');
    });

    return { success: true, count: pendingUsers.length };
  } catch (error) {
    return { success: false, error: error.toString() };
  }
}

// Menolak permintaan akses -- baris permintaan langsung dihapus dari sheet
function rejectUser(requesterUsername, targetUsername) {
  try {
    const sheet = ensureUsersSheet_();
    const users = getUsersRaw_();
    const requester = users.find(u => u.username === String(requesterUsername || '').trim());
    if (!requester || requester.role !== 'superadmin') {
      return { success: false, error: 'Akses ditolak. Hanya superadmin yang dapat menolak permintaan.' };
    }
    const target = users.find(u => u.username === String(targetUsername || '').trim());
    if (!target) {
      return { success: false, error: 'Permintaan tidak ditemukan.' };
    }
    sheet.deleteRow(target.row);
    return { success: true };
  } catch (error) {
    return { success: false, error: error.toString() };
  }
}

// Menambah akun baru -- HANYA superadmin yang boleh (langsung berstatus 'aktif')
function addUser(requesterUsername, newUsername, newPassword, newRole, newNama) {
  try {
    const sheet = ensureUsersSheet_();
    const users = getUsersRaw_();
    const requester = users.find(u => u.username === String(requesterUsername || '').trim());
    if (!requester || requester.role !== 'superadmin') {
      return { success: false, error: 'Akses ditolak. Hanya superadmin yang dapat menambah akun.' };
    }

    const uName = String(newUsername || '').trim();
    const uPass = String(newPassword || '').trim();
    const uRole = String(newRole || '').trim().toLowerCase() === 'superadmin' ? 'superadmin' : 'user';
    const uNama = String(newNama || '').trim();

    if (!uName || !uPass) {
      return { success: false, error: 'Username dan password wajib diisi.' };
    }
    if (users.some(u => u.username.toLowerCase() === uName.toLowerCase())) {
      return { success: false, error: 'Username sudah digunakan, silakan pilih yang lain.' };
    }

    const hashedPass = hashPassword_(uPass);
    sheet.appendRow([uName, hashedPass, uRole, 'aktif', uNama]);
    return { success: true };
  } catch (error) {
    return { success: false, error: error.toString() };
  }
}

// Mengedit akun (password & role) -- HANYA superadmin yang boleh
function updateUser(requesterUsername, targetUsername, newPassword, newRole, newNama) {
  try {
    const sheet = ensureUsersSheet_();
    const users = getUsersRaw_();
    const requester = users.find(u => u.username === String(requesterUsername || '').trim());
    if (!requester || requester.role !== 'superadmin') {
      return { success: false, error: 'Akses ditolak. Hanya superadmin yang dapat mengedit akun.' };
    }

    const target = users.find(u => u.username === String(targetUsername || '').trim());
    if (!target) {
      return { success: false, error: 'Akun tidak ditemukan.' };
    }

    const uPass = String(newPassword || '').trim();
    const uRole = String(newRole || '').trim().toLowerCase() === 'superadmin' ? 'superadmin' : 'user';
    const uNama = String(newNama || '').trim();

    // Cegah menurunkan role superadmin terakhir (supaya tidak ada yang terkunci dari akses admin)
    if (target.role === 'superadmin' && uRole !== 'superadmin') {
      const totalSuperadmin = users.filter(u => u.role === 'superadmin').length;
      if (totalSuperadmin <= 1) {
        return { success: false, error: 'Tidak bisa mengubah role superadmin terakhir yang tersisa.' };
      }
    }

    if (uPass) {
      const hashedPass = hashPassword_(uPass);
      sheet.getRange(target.row, 2).setValue(hashedPass);
    }
    sheet.getRange(target.row, 3).setValue(uRole);
    if (uNama) sheet.getRange(target.row, 5).setValue(uNama);
    return { success: true };
  } catch (error) {
    return { success: false, error: error.toString() };
  }
}

// Menghapus akun -- HANYA superadmin yang boleh, tidak bisa hapus diri sendiri / superadmin terakhir
function deleteUser(requesterUsername, targetUsername) {
  try {
    const sheet = ensureUsersSheet_();
    const users = getUsersRaw_();
    const requester = users.find(u => u.username === String(requesterUsername || '').trim());
    if (!requester || requester.role !== 'superadmin') {
      return { success: false, error: 'Akses ditolak. Hanya superadmin yang dapat menghapus akun.' };
    }

    const target = users.find(u => u.username === String(targetUsername || '').trim());
    if (!target) {
      return { success: false, error: 'Akun tidak ditemukan.' };
    }
    if (target.username === requester.username) {
      return { success: false, error: 'Tidak bisa menghapus akun yang sedang Anda gunakan sendiri.' };
    }
    if (target.role === 'superadmin') {
      const totalSuperadmin = users.filter(u => u.role === 'superadmin').length;
      if (totalSuperadmin <= 1) {
        return { success: false, error: 'Tidak bisa menghapus superadmin terakhir yang tersisa.' };
      }
    }

    sheet.deleteRow(target.row);
    return { success: true };
  } catch (error) {
    return { success: false, error: error.toString() };
  }
}

// ===================== MASKING SENSOR KOLOM N (CATATAN SOLVER) =====================
// Sensor 5 digit terakhir untuk nomor identitas pelanggan / tiket (10-12 digit dan KM+10-12 digit)
// Contoh: 02122412345 -> 021224*****, KM34241112345 -> KM342411*****, 143423112345 -> 1434231*****, 081326812345 -> 0813268*****
function maskNotesKolomN(text) {
  if (!text) return text === 0 ? '0' : (text || '');
  var str = String(text);
  // 1. KM diikuti 10, 11, atau 12 digit (KM + 5-7 digit depan + 5 digit bintang)
  var res = str.replace(/\b(KM[\s:-]?)(\d{5,7})(\d{5})\b/gi, function(match, p1, p2) {
    return p1 + p2 + '*****';
  });
  // 2. Angka murni 10, 11, atau 12 digit (5-7 digit depan + 5 digit bintang)
  res = res.replace(/\b(\d{5,7})(\d{5})\b/g, function(match, p1) {
    return p1 + '*****';
  });
  return res;
}

// Helper internal untuk mengekstrak data dari sheet tertentu ('Data' untuk Fixed, 'Data2' untuk Mobile).
// Struktur kolom (A-P) harus sama persis antara sheet "Data" dan "Data2".
function extractSheetRecords_(sheet, tz, sortAlphaNum) {
  if (!sheet) {
    return {
      rawRecords: [],
      filters: { tanggal: [], bulan: [], tahun: [], unit: [], sourceBy: [] }
    };
  }
  
  const lastRow = sheet.getLastRow();
  if (lastRow < 2) {
    return { rawRecords: [], filters: { tanggal: [], bulan: [], tahun: [], unit: [], sourceBy: [] } };
  }
  
  // Ambil data sekaligus dari baris 2 hingga terakhir, kolom A-P (16 kolom)
  const values = sheet.getRange(2, 1, lastRow - 1, 16).getValues();
  
  const setTanggal = new Set();
  const setBulan = new Set();
  const setTahun = new Set();
  const setUnit = new Set();
  const setKategoriL = new Set();
  const setSourceBy = new Set();
  
  const rawRecords = values
    .map(row => {
      const normRow = row.map(cell => {
        if (cell === null || cell === undefined) return "";
        if (cell instanceof Date) {
          return Utilities.formatDate(cell, tz, "yyyy-MM-dd");
        }
        return String(cell).trim();
      });

      // Sensor data privasi pada Kolom N (Notes by Solver / Catatan Solver)
      if (normRow[13]) {
        normRow[13] = maskNotesKolomN(normRow[13]);
      }

      return normRow;
    })
    .filter(normRow => {
      const hasValidRecord = (normRow[4] !== "" || normRow[6] !== "");
      if (hasValidRecord) {
        if (normRow[0] !== "") setTanggal.add(normRow[0]);
        if (normRow[1] !== "") setBulan.add(normRow[1]);
        if (normRow[2] !== "") setTahun.add(normRow[2]);
        if (normRow[9] !== "") setUnit.add(normRow[9]);
        if (normRow[11] !== "") setKategoriL.add(normRow[11]);
        if (normRow[15] !== "") setSourceBy.add(normRow[15]);
        return true;
      }
      return false;
    });
  
  return {
    rawRecords: rawRecords,
    filters: {
      tanggal: Array.from(setTanggal).sort(sortAlphaNum),
      bulan: Array.from(setBulan).sort(sortAlphaNum),
      tahun: Array.from(setTahun).sort(sortAlphaNum),
      unit: Array.from(setUnit).sort(sortAlphaNum),
      kategoriL: Array.from(setKategoriL).sort(sortAlphaNum),
      sourceBy: Array.from(setSourceBy).sort(sortAlphaNum)
    }
  };
}

// Mengambil data dashboard untuk Fixed ('Data') dan Mobile ('Data2').
// Mengembalikan objek dengan property .fixed dan .mobile, serta tetap menyertakan .rawRecords & .filters
// untuk kompatibilitas backward.
function getDashboardData() {
  try {
    const ss = SpreadsheetApp.getActiveSpreadsheet();
    const tz = Session.getScriptTimeZone();
    const sortAlphaNum = (a, b) => String(a).localeCompare(String(b), undefined, { numeric: true, sensitivity: 'base' });
    
    const sheetFixed = ss.getSheetByName('Data');
    const sheetMobile = ss.getSheetByName('Data2');
    
    if (!sheetFixed && !sheetMobile) {
      return {
        rawRecords: [],
        filters: { tanggal: [], bulan: [], tahun: [], unit: [], sourceBy: [] },
        fixed: { rawRecords: [], filters: { tanggal: [], bulan: [], tahun: [], unit: [], sourceBy: [] } },
        mobile: { rawRecords: [], filters: { tanggal: [], bulan: [], tahun: [], unit: [], sourceBy: [] } },
        error: 'Sheet "Data" maupun "Data2" tidak ditemukan di spreadsheet ini.'
      };
    }
    
    const fixedData = extractSheetRecords_(sheetFixed, tz, sortAlphaNum);
    const mobileData = extractSheetRecords_(sheetMobile, tz, sortAlphaNum);
    
    return {
      rawRecords: fixedData.rawRecords,
      filters: fixedData.filters,
      fixed: fixedData,
      mobile: mobileData
    };
  } catch (error) {
    Logger.log("Error pada getDashboardData: " + error.toString());
    return { 
      rawRecords: [], 
      filters: { tanggal: [], bulan: [], tahun: [], unit: [], sourceBy: [] },
      fixed: { rawRecords: [], filters: { tanggal: [], bulan: [], tahun: [], unit: [], sourceBy: [] } },
      mobile: { rawRecords: [], filters: { tanggal: [], bulan: [], tahun: [], unit: [], sourceBy: [] } },
      error: error.toString() 
    };
  }
}

// ===================== INTEGRASI TELEGRAM: LAPORAN HARIAN & PERIOD COMPARISON (MTD) =====================
const TELEGRAM_CONFIG = {
  BOT_TOKEN: '8732702174:AAGmDyX4_AJb0XpWgGX1MluWbY0M608OPaI',
  CHAT_ID: '-5555763422' // Grup Telegram: REPORT DASHBOARD MATA
};

/**
 * Mengirim pesan teks ke Telegram menggunakan Telegram Bot API
 */
function sendTelegramMessage(text, parseMode) {
  const props = PropertiesService.getScriptProperties();
  const token = props.getProperty('TELEGRAM_BOT_TOKEN') || TELEGRAM_CONFIG.BOT_TOKEN;
  const chatId = props.getProperty('TELEGRAM_CHAT_ID') || TELEGRAM_CONFIG.CHAT_ID;
  
  if (!token || !chatId) {
    return { success: false, error: 'Token atau Chat ID Telegram belum dikonfigurasi.' };
  }
  
  const url = 'https://api.telegram.org/bot' + token + '/sendMessage';
  const payload = {
    chat_id: chatId,
    text: text,
    parse_mode: parseMode || 'HTML',
    disable_web_page_preview: true
  };
  
  const options = {
    method: 'post',
    contentType: 'application/json',
    payload: JSON.stringify(payload),
    muteHttpExceptions: true
  };
  
  try {
    const response = UrlFetchApp.fetch(url, options);
    const result = JSON.parse(response.getContentText());
    return { success: result.ok, result: result };
  } catch (e) {
    Logger.log('Error sendTelegramMessage: ' + e.toString());
    return { success: false, error: e.toString() };
  }
}

/**
 * Uji coba koneksi bot Telegram
 */
function testTelegramConnection() {
  const msg = '🚀 <b>Koneksi Bot Telegram Berhasil!</b>\n\nSistem Google Apps Script MATA terhubung sempurna dengan bot @agentmata_bot.';
  return sendTelegramMessage(msg, 'HTML');
}

/**
 * Menghasilkan dan mengirimkan laporan Telegram:
 * 1. Pengecekan inputan tiket di hari ini
 * 2. Period Comparison (MTD MoM): Rentang tanggal 1–X bulan ini vs 1–X bulan lalu
 */
function generateTelegramMtdReport() {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const tz = Session.getScriptTimeZone();
  const sortAlphaNum = (a, b) => String(a).localeCompare(String(b), undefined, { numeric: true, sensitivity: 'base' });
  
  const sheetFixed = ss.getSheetByName('Data');
  const sheetMobile = ss.getSheetByName('Data2');
  
  const fixedRecs = sheetFixed ? extractSheetRecords_(sheetFixed, tz, sortAlphaNum).rawRecords : [];
  const mobileRecs = sheetMobile ? extractSheetRecords_(sheetMobile, tz, sortAlphaNum).rawRecords : [];
  const allRecords = fixedRecs.concat(mobileRecs);
  
  const today = new Date();
  const todayDay = today.getDate();
  const monthNames = ['JANUARI', 'FEBRUARI', 'MARET', 'APRIL', 'MEI', 'JUNI', 'JULI', 'AGUSTUS', 'SEPTEMBER', 'OKTOBER', 'NOVEMBER', 'DESEMBER'];
  const todayMonthName = monthNames[today.getMonth()];
  const todayYear = String(today.getFullYear());
  const todayFormatted = Utilities.formatDate(today, tz, 'EEEE, dd MMMM yyyy');
  const timeFormatted = Utilities.formatDate(today, tz, 'HH:mm');
  
  // 1. Cek inputan hari ini (Kolom 0 = tanggal, Kolom 1 = bulan, Kolom 2 = tahun)
  const isMatchToday = function(r) {
    const tgl = String(r[0] || '').trim();
    const bln = String(r[1] || '').trim().toUpperCase();
    const thn = String(r[2] || '').trim();
    return (tgl === String(todayDay) && bln === todayMonthName && thn === todayYear);
  };
  
  const todayFixed = fixedRecs.filter(isMatchToday);
  const todayMobile = mobileRecs.filter(isMatchToday);
  const totalToday = todayFixed.length + todayMobile.length;
  
  // 2. Kalkulasi Period Comparison (MTD Comparison)
  const monthsInDataset = [];
  const monthSet = new Set();
  allRecords.forEach(function(r) {
    const b = String(r[1] || '').trim().toUpperCase();
    if (b && !monthSet.has(b)) {
      monthSet.add(b);
      monthsInDataset.push(b);
    }
  });
  
  let currMonth = todayMonthName;
  let prevMonth = today.getMonth() > 0 ? monthNames[today.getMonth() - 1] : 'DESEMBER';
  
  if (!monthSet.has(currMonth) && monthsInDataset.length > 0) {
    currMonth = monthsInDataset[monthsInDataset.length - 1];
    prevMonth = monthsInDataset.length > 1 ? monthsInDataset[monthsInDataset.length - 2] : '';
  }
  
  // Cari cut-off tanggal tertinggi pada currMonth (utamakan dataset Fixed)
  const targetMtdPool = fixedRecs.length > 0 ? fixedRecs : allRecords;
  let maxDay = 0;
  targetMtdPool.forEach(function(r) {
    if (String(r[1] || '').trim().toUpperCase() === currMonth) {
      const d = parseInt(r[0], 10);
      if (!isNaN(d) && d > maxDay) maxDay = d;
    }
  });
  if (maxDay === 0) maxDay = todayDay;
  
  // Filter MTD (Exclude Sanggahan Diterima = Net Bad Ticket)
  const isNotSanggahan = function(r) {
    return !String(r[14] || '').toUpperCase().includes('SANGGAHAN DITERIMA');
  };
  
  const isCurrMtd = function(r) {
    const bln = String(r[1] || '').trim().toUpperCase();
    const d = parseInt(r[0], 10);
    return bln === currMonth && !isNaN(d) && d <= maxDay && isNotSanggahan(r);
  };
  
  const isPrevMtd = function(r) {
    const bln = String(r[1] || '').trim().toUpperCase();
    const d = parseInt(r[0], 10);
    return bln === prevMonth && !isNaN(d) && d <= maxDay && isNotSanggahan(r);
  };
  
  const currMtdRecords = targetMtdPool.filter(isCurrMtd);
  const prevMtdRecords = targetMtdPool.filter(isPrevMtd);
  
  const currCount = currMtdRecords.length;
  const prevCount = prevMtdRecords.length;
  
  const diffCount = currCount - prevCount;
  let pctDiff = 0;
  if (prevCount > 0) {
    pctDiff = Math.round(((diffCount / prevCount) * 100));
  }
  
  const trendIcon = diffCount < 0 ? '🟢' : (diffCount > 0 ? '🔴' : '🟡');
  const trendStatus = diffCount < 0 ? 'TURUN' : (diffCount > 0 ? 'NAIK' : 'STABIL');
  const signStr = diffCount > 0 ? '+' : '';

  const formatMonthShort = function(m) {
    if (!m) return '';
    const s = m.trim();
    return s.charAt(0).toUpperCase() + s.substring(1, 3).toLowerCase();
  };
  const cShort = formatMonthShort(currMonth);
  const pShort = formatMonthShort(prevMonth);
  
  // Top Categories Comparison
  const catCurr = {};
  const catPrev = {};
  currMtdRecords.forEach(function(r) {
    const k = String(r[11] || 'LAINNYA').trim();
    catCurr[k] = (catCurr[k] || 0) + 1;
  });
  prevMtdRecords.forEach(function(r) {
    const k = String(r[11] || 'LAINNYA').trim();
    catPrev[k] = (catPrev[k] || 0) + 1;
  });
  
  const sortedCats = Object.keys(catCurr).sort(function(a, b) {
    return catCurr[b] - catCurr[a];
  }).slice(0, 5);
  
  // Unit Comparison
  const unitCurr = {};
  const unitPrev = {};
  currMtdRecords.forEach(function(r) {
    const u = String(r[9] || '').trim();
    if (u) unitCurr[u] = (unitCurr[u] || 0) + 1;
  });
  prevMtdRecords.forEach(function(r) {
    const u = String(r[9] || '').trim();
    if (u) unitPrev[u] = (unitPrev[u] || 0) + 1;
  });
  
  const sortedUnits = Object.keys(unitCurr).sort(function(a, b) {
    return unitCurr[b] - unitCurr[a];
  }).slice(0, 5);
  
  // Format Pesan Telegram
  let msg = `🔔 <b>LAPORAN HARIAN & PERIOD COMPARISON MATA</b>\n`;
  msg += `📅 <b>Tanggal Cek:</b> ${todayFormatted} | ${timeFormatted} WIB\n\n`;
  
  msg += `━━━━━━━━━━━━━━━━━━━━━━━━\n`;
  msg += `📍 <b>1. STATUS INPUTAN HARI INI (${todayDay} ${todayMonthName})</b>\n`;
  msg += `━━━━━━━━━━━━━━━━━━━━━━━━\n`;
  if (totalToday > 0) {
    msg += `✅ <b>Ditemukan ${totalToday} Inputan Tiket Baru Hari Ini!</b>\n`;
    msg += `• Fixed  : <b>${todayFixed.length}</b> tiket\n`;
    msg += `• Mobile : <b>${todayMobile.length}</b> tiket\n\n`;
  } else {
    msg += `⚠️ <i>Belum ada inputan baru untuk hari ini.</i>\n`;
    msg += `<i>(Cut-off data inputan terakhir per tanggal ${maxDay} ${currMonth} 2026)</i>\n\n`;
  }
  
  msg += `━━━━━━━━━━━━━━━━━━━━━━━━\n`;
  msg += `📈 <b>2. PERIOD COMPARISON (MTD MoM)</b>\n`;
  msg += `<b>Rentang Cut-Off: 1–${maxDay} ${currMonth} vs 1–${maxDay} ${prevMonth} 2026</b>\n`;
  msg += `━━━━━━━━━━━━━━━━━━━━━━━━\n`;
  msg += `• MTD Bulan Ini (${currMonth})  : <b>${currCount} Tiket</b>\n`;
  msg += `• MTD Bulan Lalu (${prevMonth}) : <b>${prevCount} Tiket</b>\n`;
  msg += `• Tren Evaluasi        : ${trendIcon} <b>${trendStatus} ${signStr}${pctDiff}% (${signStr}${diffCount} Tiket)</b>\n\n`;
  
  if (sortedCats.length > 0) {
    msg += `📌 <b>Perbandingan Top Kategori Bad Ticket:</b>\n`;
    sortedCats.forEach(function(cat, idx) {
      const cVal = catCurr[cat] || 0;
      const pVal = catPrev[cat] || 0;
      const diff = cVal - pVal;
      let pct = 0;
      if (pVal > 0) {
        pct = Math.round(((diff) / pVal) * 100);
      } else if (cVal > 0) {
        pct = 100;
      }
      const icon = diff < 0 ? '🟢 Turun' : (diff > 0 ? '🔴 Naik' : '➖ Stabil');
      const sign = diff > 0 ? '+' : '';
      msg += `${idx + 1}. <b>${cat}</b>\n   • ${cShort}: <b>${cVal}</b> vs ${pShort}: <b>${pVal}</b> [${icon} ${sign}${pct}% (${sign}${diff})]\n`;
    });
    msg += `\n`;
  }
  
  if (sortedUnits.length > 0) {
    msg += `🏢 <b>Perbandingan Per Unit:</b>\n`;
    sortedUnits.forEach(function(u) {
      const cVal = unitCurr[u] || 0;
      const pVal = unitPrev[u] || 0;
      const diff = cVal - pVal;
      let pct = 0;
      if (pVal > 0) {
        pct = Math.round(((diff) / pVal) * 100);
      } else if (cVal > 0) {
        pct = 100;
      }
      const icon = diff < 0 ? '🟢 Turun' : (diff > 0 ? '🔴 Naik' : '➖ Stabil');
      const sign = diff > 0 ? '+' : '';
      msg += `• <b>${u}</b>: ${cShort} <b>${cVal}</b> vs ${pShort} <b>${pVal}</b> [${icon} ${sign}${pct}% (${sign}${diff})]\n`;
    });
  }
  
  msg += `━━━━━━━━━━━━━━━━━━━━━━━━\n`;
  msg += `🔗 <a href="https://dashboard-mata.vercel.app">Buka Dashboard MATA</a>`;
  
  return sendTelegramMessage(msg, 'HTML');
}

/**
 * Pengaturan Pemicu Jadwal Otomatis (Daily Trigger jam 15:00 WIB)
 * Jalankan fungsi ini sekali dari editor Google Apps Script jika ingin laporan dikirim otomatis setiap hari pukul 15.00 WIB
 */
function setupDailyTelegramTrigger() {
  // Hapus trigger lama jika sudah ada
  const triggers = ScriptApp.getProjectTriggers();
  triggers.forEach(function(t) {
    if (t.getHandlerFunction() === 'generateTelegramMtdReport') {
      ScriptApp.deleteTrigger(t);
    }
  });
  
  // Buat trigger harian pukul 15:00 - 16:00 WIB
  ScriptApp.newTrigger('generateTelegramMtdReport')
    .timeBased()
    .atHour(15)
    .everyDays(1)
    .inTimezone('Asia/Jakarta')
    .create();
    
  Logger.log('Trigger harian jam 15:00 WIB berhasil dibuat!');
}
