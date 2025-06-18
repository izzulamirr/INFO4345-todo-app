<?php

namespace App\Http\Controllers;
use App\Models\Todo;
use App\Models\User;
use App\Models\UserRole;
use App\Models\RolePermission;
use App\Models\Role;
use App\Models\Permission;


use Illuminate\Http\Request;

class AdminController extends Controller
{
    // Show the admin dashboard with all users and their todos
    public function dashboard()
    {
        $hasTodos = \App\Models\Todo::exists();
        $users = User::with('userRole', 'todos')->get();
        return view('admin.dashboard', compact('users', 'hasTodos'));
    }

    // Delete a user
    public function destroy($id)
    {
        $user = User::findOrFail($id);
        $user->delete();
        return redirect()->route('admin.dashboard')->with('success', 'User deleted successfully.');
    }

    // Deactivate a user
    public function deactivate($id)
    {
        $user = User::findOrFail($id);
        $user->is_active = false;
        $user->save();
        return redirect()->route('admin.dashboard')->with('success', 'User deactivated.');
    }

    // Activate a user
    public function activate($id)
    {
        $user = User::findOrFail($id);
        $user->is_active = true;
        $user->save();
        return redirect()->route('admin.dashboard')->with('success', 'User activated.');
    }

    public function permissions()
{
    $roles = UserRole::select('RoleID', 'RoleName')->distinct()->get();
    $permissions = ['Create', 'Retrieve', 'Update', 'Delete'];
    return view('Admin.permission', compact('roles', 'permissions'));
}

public function updatePermissions(Request $request)
{
    $roles = UserRole::select('RoleID', 'RoleName')->distinct()->get();
    foreach ($roles as $role) {
        // Remove all permissions for this role
        RolePermission::where('RoleID', $role->RoleID)->delete();
        // Add selected permissions
        if ($request->has("permissions.{$role->RoleID}")) {
            foreach ($request->input("permissions.{$role->RoleID}") as $perm) {
                RolePermission::create([
                    'RoleID' => $role->RoleID,
                    'Description' => $perm,
                ]);
            }
        }
    }
    return redirect()->back()->with('success', 'Permissions updated!');
}
    
}