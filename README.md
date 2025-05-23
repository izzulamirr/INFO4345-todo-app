# Laravel To DO app Assignment 

1. Model file Enhancement.
   # added more attributes in the model
   -   'nickname',
        'phone_no', 
        'city',
        'avatar'

2. Edit the registrations and login controller
   # to reduces the amount of functions uses in the controller


3. Created 2 request file login and registrations
   # implement the input validations in the request
   - 'name' => ['required', 'string', 'regex:/^[A-Za-z\s]+$/', 'max:255'],
            'email' => ['required', 'string', 'email', 'max:255', 'unique:users'],
            'password' => ['required', 'string', 'min:8', 'confirmed'],
            'nickname' => ['nullable', 'string', 'max:255'],
            'phone_no' => ['nullable', 'string', 'regex:/^\d{10,15}$/'], // Only digits, 10-15 characters
            'city' => ['nullable', 'string', 'max:255'],
   # uses regex as a rules for the registrations


   4. Created profile pages
      # handles changes of informations and credentials.
      - able to edit and save changes in the database.
      - able to deleted and update users from the database


Lab Assignment 2

1. Fortify laravel
   # modify the fortifyservice provider file
    RateLimiter::for('login', function (Request $request) {
            $email = (string) $request->email;
    
            return Limit::perMinute(3)->by($email . '|' . $request->ip());
        });

        RateLimiter::for('two-factor', function (Request $request) {
            return Limit::perMinute(5)->by($request->session()->get('login.id'));
        });
    }
   - created a 2 factor authentication using recovery codes
   - sending recovery codes after enable 2FA in the pages setting.
  
2. Encrypt password using bcrypt or argon2
   # add bcrypt in the registercontroller (  'password' => bcrypt($validated['password']),)
   # in the databse will encrypted password

3. Rate limiter 3 times
   # in the logincontroller function login
   public function login(LoginRequest $request)
{
    $credentials = $request->only('email', 'password');
    $throttleKey = $request->email . '|' . $request->ip(); // Unique key for rate limiting

    // Check if the user is throttled
    if (RateLimiter::tooManyAttempts($throttleKey, 3)) {
        $seconds = RateLimiter::availableIn($throttleKey);

   - the (throttlekey, 3) indicates the times of password can be entered wrongly before the system prevent any input of password for a set amount of duration.
  
4. added salted in password

    # in the users database, password will addded salted security in the password.

   - add a new attributes in the user database which is salt for the password
  protected $fillable = [
        'name',
        'email',
        'password',
        'salt',
     
   - then the registercontroller edited to stored the salted password in the databased during register a new user
     $user = User::create([
            'name' => $validated['name'],
            'email' => $validated['email'],
            'salt' => $salt, // Store the generated salt
