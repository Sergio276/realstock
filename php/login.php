<?php 
require 'config.php';

if (isset($_POST['login'])) {
    $user = $_POST['user'];
	$password = $_POST['password'];

	$stmt = $conn->prepare("SELECT usuario_id, usuario, contrasena, estado FROM tbl_usuario WHERE usuario = ?");
	$stmt->bind_param("s", $user);
    $stmt->execute();
	$stmt->bind_result($usuario_id, $usuario, $contrasena, $estado);

    if ($stmt->fetch()) {
        if (password_verify($password, $contrasena)) {
            if ($estado == "activo") {
                session_start();
                $_SESSION['user_id'] = $usuario_id;
                $_SESSION['username'] = $usuario;
                echo '<script type="text/javascript">
                alert("Bienvenid@: '. $usuario .'");
                window.location.href = "../principal.php";
                </script>';
            } else {
                echo '<script type="text/javascript">
                alert("El usuario se encuentra desactivado");
                window.location.href = "../index.php";
                </script>';
            }
        } else {
            echo '<script type="text/javascript">
            alert("Usuario y/o contraseña erroneos");
            window.location.href = "../index.php";
            </script>';
        }
    } else {
        echo '<script type="text/javascript">
		alert("No se encontró registrado al usuario: '. $user .'");
		window.location.href = "../index.php";
		</script>';
    }
    $stmt->close();
    $conn->close();
}
