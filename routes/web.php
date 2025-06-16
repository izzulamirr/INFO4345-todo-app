<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\TodoController;
use App\Http\Controllers\ProfileController;
use App\Http\Controllers\Auth\LoginController;
use App\Http\Controllers\AdminController;

/*
|--------------------------------------------------------------------------
| Web Routes
|--------------------------------------------------------------------------
|
| Here is where you can register web routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "web" middleware group. Make something great!
|
*/

Route::get('/', function () {
    return view('welcome');
});


Auth::routes();

Route::post('/logout', [LoginController::class, 'logout'])->name('logout');


Route::middleware(['auth'])->group(function () {
    Route::get('/todo', [TodoController::class, 'index'])->name('todo.index');
Route::get('/todo/create', [TodoController::class, 'create'])->name('todo.create');
Route::post('/todo', [TodoController::class, 'store'])->name('todo.store');
Route::get('/todo/{todo}', [TodoController::class, 'show'])->name('todo.show');
Route::get('/todo/{todo}/edit', [TodoController::class, 'edit'])->name('todo.edit');
Route::put('/todo/{todo}', [TodoController::class, 'update'])->name('todo.update');
Route::delete('/todo/{todo}', [TodoController::class, 'destroy'])->name('todo.destroy');
});


Route::middleware(['auth'])->group(function () {
    Route::get('/profile', [ProfileController::class, 'edit'])->name('profile.edit');
    Route::put('/profile', [ProfileController::class, 'update'])->name('profile.update');
    Route::delete('/profile', [ProfileController::class, 'destroy'])->name('profile.destroy');

    Route::view('/two-factor-settings', 'auth.two-factor-setting')->name('two-factor-settings');
});




//Admin

Route::middleware(['auth', 'admin'])->group(function () {
    Route::get('/admin', [AdminController::class, 'dashboard'])->name('admin.dashboard');
    Route::delete('/admin/users/{id}', [AdminController::class, 'destroy'])->name('users.destroy');
    Route::post('/admin/users/{id}/deactivate', [AdminController::class, 'deactivate'])->name('users.deactivate');
    Route::post('/admin/users/{id}/activate', [AdminController::class, 'activate'])->name('users.activate');
});


Route::middleware(['auth', 'admin'])->group(function () {
    Route::get('/admin/permissions', [AdminController::class, 'permissions'])->name('admin.permissions');
    Route::post('/admin/permissions', [AdminController::class, 'updatePermissions'])->name('admin.permissions.update');
});