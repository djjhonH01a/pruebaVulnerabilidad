// Vulnerable a SQL Injection
$username = $_GET['user'];
$password = $_GET['pass'];

$query = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
$result = mysqli_query($conn, $query);
