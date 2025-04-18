@extends('layouts.app')
@section('content')
<div class="container">
  <br>
  <div class="row justify-content-center">
    <div class="col-md-6">
      <h2>To-Do List</h2>
    </div>
    <div class="col-md-6">
      <div class="float-right">
        <a href="{{ route('todo.create') }}" class="btn btn-primary">
          <i class="fa fa-plus"></i> Add New To do
        </a>
      </div>
    </div>
    <br>
    <div class="col-md-12">
      @if (session('success'))
        <div class="alert alert-success" role="alert">
          {{ session('success') }}
        </div>
      @endif
      @if (session('error'))
        <div class="alert alert-danger" role="alert">
          {{ session('error') }}
        </div>
      @endif
      <table class="table table-bordered">
        <thead class="thead-light">
          <tr>
            <th width="5%">#</th>
            <th>Task Name</th>
            <th width="10%"><center>Task Status</center></th>
            <th width="14%"><center>Action</center></th>
          </tr>
        </thead>
        <tbody>
        @forelse ($todos as $todo)
    <tr>
        <th>{{ $todo->id }}</th>
        <td>{{ $todo->title }}</td>
        <td><center>{{ ucfirst($todo->status) }}</center></td>
        <td>
            <div class="d-flex justify-content-center">
                <a href="{{ route('todo.show', $todo->id) }}" class="btn btn-info btn-sm mr-2" aria-label="View Todo">
                    View
                </a>
                <a href="{{ route('todo.edit', $todo->id) }}" class="btn btn-warning btn-sm mr-2" aria-label="Edit Todo">
                    Edit
                </a>
                <form action="{{ route('todo.destroy', $todo->id) }}" method="post">
                    @csrf
                    @method('DELETE')
                    <button class="btn btn-danger btn-sm" type="submit" aria-label="Delete Todo" onclick="return confirm('Are you sure you want to delete this todo?')">
                        Delete
                    </button>
                </form>
            </div>
        </td>
    </tr>
@empty
    <tr>
        <td colspan="4">
            <center>No todos found. <a href="{{ route('todo.create') }}">Create a new todo</a>.</center>
        </td>
    </tr>
@endforelse
        </tbody>
      </table>
    </div>
  </div>
</div>
@endsection