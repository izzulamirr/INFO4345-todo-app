<?php

namespace App\Http\Controllers;

use App\Models\Todo;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Session;

class TodoController extends Controller
{
    /**
     * Display a listing of the resource.
     */
    public function index()
    {
        $userId = Auth::user()->id;
        $todos = Todo::where(['user_id' => $userId])->get();
        return view('todo.list', ['todos' => $todos]);
    }

    /**
     * Show the form for creating a new resource.
     */
    public function create()
    {
        if (!auth()->user()->permissions()->where('Description', 'Create')->count()) {
        abort(403, 'Unauthorized');
    }
    return view('todo.add');
    }

    /**
     * Store a newly created resource in storage.
     */
    public function store(Request $request)
    {
        $userId = Auth::user()->id;

        $validated = $request->validate([
            'title' => 'required|string|max:255',
            'description' => 'nullable|string', // Allow description to be optional
            'status' => 'required|in:pending,completed',
        ]);
        
        $input = $request->input();
        $input['user_id'] = $userId;
        $todoStatus = Todo::create($input);

        if ($todoStatus) {
            $message = 'Todo successfully added';
            $type = 'success';
        } else {
            $message = 'Oops, something went wrong. Todo not saved';
            $type = 'error';
        }

        return redirect('/todo')->with($type, $message);
    }

    /**
     * Display the specified resource.
     */
    public function show(Todo $todo)
    {
        $userId = Auth::user()->id;
        $todo = Todo::where(['user_id' => $userId, 'id' => $todo->id])->first();
        if (!$todo) {
            return redirect('todo')->with('error', 'Todo not found');
        }
        return view('todo.view', ['todo' => $todo]);
    }

    /**
     * Show the form for editing the specified resource.
     */
    
         public function edit($id)
    {
        $todo = Todo::findOrFail($id);
        return view('todo.edit', compact('todo'));
    }
    

    /**
     * Update the specified resource in storage.
     */
   public function update(Request $request, $id)
    {
       $todo = Todo::findOrFail($id);
    $todo->title = $request->input('title');
    $todo->description = $request->input('description');
    $todo->status = $request->input('status');
    $todo->save();
    return redirect()->route('todo.index')->with('success', 'Todo updated successfully!');
}

    /**
     * Remove the specified resource from storage.
     */
    public function destroy(Todo $todo)
    {
        $userId = Auth::user()->id;
        // Ensure the Todo belongs to the authenticated user
    $todo = Todo::where(['user_id' => $userId, 'id' => $todo->id])->first();

    if (!$todo) {
        return redirect('todo')->with('error', 'Todo not found');
    }

    // Attempt to delete the Todo
    if ($todo->delete()) {
        return redirect('todo')->with('success', 'Todo deleted successfully');
    }

    return redirect('todo')->with('error', 'Oops, something went wrong. Todo not deleted successfully');
    }
}
