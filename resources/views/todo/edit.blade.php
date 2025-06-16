@extends('layouts.app')
@section('content')
<div class="container">
  <br>
  <div class="row justify-content-center">
    <div class="col-md-12 text-center">
      <h2>Edit Todo</h2>
    </div>
  </div>
  <br>
  <div class="row justify-content-center">
    <div class="col-md-8">
      <form action="{{ route('todo.update', $todo->id) }}" method="POST">
        @csrf
        @method('PUT')
        <div class="form-group">
          <label for="title">Title:</label>
          <input 
            type="text" 
            class="form-control" 
            id="title" 
            name="title" 
            value="{{ old('title', $todo->title) }}" 
            aria-label="Todo Title">
        </div>
        <div class="form-group">
          <label for="description">Description:</label>
          <textarea 
            name="description" 
            class="form-control" 
            id="description" 
            rows="5" 
            aria-label="Todo Description">{{ old('description', $todo->description) }}</textarea>
        </div>
        <div class="form-group">
          <label for="status">Select Todo Status:</label>
          <select 
            class="form-control" 
            id="status" 
            name="status" 
            aria-label="Todo Status">
            <option value="pending" {{ old('status', $todo->status) == 'pending' ? 'selected' : '' }}>Pending</option>
            <option value="completed" {{ old('status', $todo->status) == 'completed' ? 'selected' : '' }}>Completed</option>
          </select>
        </div>
        <div class="d-flex justify-content-center mt-4">
          <a href="{{ route('todo.index') }}" class="btn btn-secondary mr-2" aria-label="Back to Todo List">Back</a>
          <button type="submit" class="btn btn-success" aria-label="Update Todo">Update</button>
        </div>
      </form>
    </div>
  </div>
</div>
@endsection