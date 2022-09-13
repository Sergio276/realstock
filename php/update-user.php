<?php
if (isset($_POST['update'], $_GET['user_id'])) {
    require 'config.php';

    $user = $_POST['user'];
    $password = $_POST['password'];
    $confirm_pass = $_POST['confirm_pass'];
    $email = $_POST['email'];
    $name = $_POST['name'];
    $last_name = $_POST['last_name'];
    $status = $_POST['status'];

    if ($password !== $confirm_pass) {
        echo '<script type="text/javascript">
        alert("Las contraseñas no coinciden. Intente de nuevo");
        window.location.href = "../frm_registrar-usuarios.php";
        </script>';
        exit();
    }

    $user_id = $_GET['user_id'];

    if ($password !== "") {
        $uppercase = preg_match('@[A-Z]@', $password);
        $lowercase = preg_match('@[a-z]@', $password);
        $number    = preg_match('@[0-9]@', $password);

        if (!$uppercase || !$lowercase || !$number || strlen($password) < 8) {
            echo '<script type="text/javascript">
                alert("La contraseña no cumple con alguno de los requisitos de tener al menos una letra mayúscula, minúscula y un número.");
                window.location.href = "../frm_registrar-usuarios.php";
                </script>';
        } else {
            $password = password_hash($password, PASSWORD_DEFAULT, array('cost' => 12));

            $stmt = $conn->prepare("UPDATE tbl_usuario SET usuario = ?, contrasena = ?, estado = ?, email = ?, nombres = ?, apellidos = ? WHERE usuario_id = '$user_id'");
            $stmt->bind_param('ssssss', $user, $password, $status, $email, $name, $last_name);
        }
    } else {
        $stmt = $conn->prepare("UPDATE tbl_usuario SET usuario = ?, estado = ?, email = ?, nombres = ?, apellidos = ? WHERE usuario_id = '$user_id'");
        $stmt->bind_param('sssss', $user, $status, $email, $name, $last_name);
    }

    $stmt->execute();
    if (($stmt) && ($stmt->affected_rows == 1)) {
        echo '<script type="text/javascript">
            alert("Se actualizó la información de: ' . $user . '");
            window.location.href = "../frm_registrar-usuarios.php";
            </script>';
    } else {
        echo '<script type="text/javascript">
            alert("No se actualizó la información");
            window.location.href = "../frm_registrar-usuarios.php";
            </script>';
    }
}
