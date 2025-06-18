@extends('layouts.app')

@section('content')
<div class="container">
    <h2>User Management</h2>
    <div class="mb-3 d-flex justify-content-end">
        <a href="{{ route('admin.permissions') }}" class="btn btn-secondary">
            Manage Role Permissions
        </a>
    </div>
    <table class="table table-bordered">
        <thead class="table-light">
            <tr>
                <th>Name</th>
                <th>Email</th>
                <th>Role</th>
                <th>Status</th>
                <th>To-Do Tasks</th>
                <th>Actions</th>
            </tr>
        </thead>
        <tbody>
        @foreach($users as $user)
            <tr>
                <td>{{ $user->name }}</td>
                <td>{{ $user->email }}</td>
                <td>{{ $user->userRole->RoleName ?? 'N/A' }}</td>
                <td>
                                @if($user->todos)
                        <ul class="mb-0">
                            @foreach($user->todos as $todo)
                                <li>Active</li>
                            @endforeach
                        </ul>
                    @else
                        <span class="text-muted">Not active</span>
                    @endif
                </td>
                <td>
                    @if($user->todos && $user->todos->count())
                        <ul class="mb-0">
                            @foreach($user->todos as $todo)
                                <li>{{ $todo->title }}</li>
                            @endforeach
                        </ul>
                    @else
                        <span class="text-muted">No tasks</span>
                    @endif
                </td>
                <td>
                    <!-- Example action buttons (implement routes and logic as needed) -->
                    <form action="{{ route('users.destroy', $user->id) }}" method="POST" style="display:inline;">
                        @csrf
                        @method('DELETE')
                        <button class="btn btn-danger btn-sm" onclick="return confirm('Delete this user?')">Delete</button>
                    </form>
                    @if(isset($user->is_active))
                        @if($user->is_active)
                            <form action="{{ route('users.deactivate', $user->id) }}" method="POST" style="display:inline;">
                                @csrf
                                <button class="btn btn-warning btn-sm">Deactivate</button>
                            </form>
                        @else
                            <form action="{{ route('users.activate', $user->id) }}" method="POST" style="display:inline;">
                                @csrf
                                <button class="btn btn-success btn-sm">Activate</button>
                            </form>
                        @endif
                    @endif
                </td>
            </tr>
        @endforeach
        </tbody>
    </table>
</div>
@endsection