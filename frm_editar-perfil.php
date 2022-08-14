<?php require_once './php/session-data.php' ?>
<!DOCTYPE html>
<html lang="es">

<head>
  <meta charset="UTF-8" />
  <meta http-equiv="X-UA-Compatible" content="IE=edge" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Real Stock</title>
  <link rel="shortcut icon" href="img/favicon.ico" type="image/x-icon">
  <link rel="stylesheet" href="css/estilos.css" />
  <link rel="preconnect" href="https://fonts.googleapis.com" />
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
  <link href="https://fonts.googleapis.com/css2?family=Josefin+Sans:wght@300&display=swap" rel="stylesheet" />
  <script defer src="js/script.js"></script>
  <script defer src="https://kit.fontawesome.com/707789a0bc.js" crossorigin="anonymous"></script>
</head>

<body>
  <nav>
    <div class="logo">
      <img src="img/logo.png" alt="" />
    </div>
    <div class="links">
      <ul>
        <li class="link">
          <a href="principal.php">
            <i class="fa-solid fa-house-chimney"></i> Inicio
          </a>
        </li>
        <li class="link">
          <a href="frm_registrar-usuarios.php">
            <i class="fa-solid fa-user-group"></i> Usuarios
          </a>
        </li>
        <li class="link">
          <a href="inventarios.php">
            <i class="fa-solid fa-cart-flatbed"></i> Inventarios
          </a>
        </li>
      </ul>
    </div>
  </nav>
  <div class="wrapper">
    <header>
      <div class="section-header">
        <div class="hamburger-menu">
          <span></span><span></span><span></span>
        </div>
        <div class="location-source">
          <a href="principal.php"><i class="fa-solid fa-house-chimney"></i> Inicio</a> / Perfil
        </div>
      </div>
      <div class="section-header">
        <div class="user-tag">
          <a href="#"><i class="fa-solid fa-circle-user"></i><?php echo $_SESSION['username'] ?></a>
        </div>
        <div class="btn-logout">
          <a href="./php/logout.php"><i class="fa-solid fa-right-from-bracket"></i></a>
        </div>
      </div>
    </header>
    <div class="content">
      <div class="content_usu"><br><br>
        <img src="img/circle-user-solid.svg" /><br><br>
        <?php
        include './php/config.php';
        $user_id = $_SESSION['user_id'];
        $query = "SELECT email, nombres, apellidos FROM tbl_usuario WHERE usuario_id = '$user_id'";
        $result = mysqli_query($conn, $query);
        
        if ($result) {
          foreach ($result as $row) {
            $email = $row['email'];
            $name = $row['nombres'];
            $last_name = $row['apellidos'];
          }
        } else {
          echo '<script type="text/javascript">
                alert("Error al obtener datos del usuario");
                </script>';
        }
        ?>
        <p><b>Nombres: </b><?php echo $name ?></p><br>
        <p><b>Apellidos: </b><?php echo $last_name ?></p><br>
        <p><b>Correo Electronico: </b><?php echo $email ?></p><br>
        <button class="btn btn-green" data-btn-modal="true" data-modal="#m-perfil-usuario">Editar información</button>
      </div>
      <div class="modal-wrapper" id="m-perfil-usuario">
        <div class="modal">
          <div class="modal-header">
            <div>Editar información de usuario</div>
            <i class="fa-solid fa-xmark" data-btn-close="modal"></i>
          </div>
          <div class="modal-content">
            <form action="./php/update-account.php?user_id=<?php echo $_SESSION['user_id'] ?>" method="post" autocomplete="off">
              <div class="form-section">
                <label for="">Nombres:</label>
                <input type="text" name="name" placeholder="Ingrese los nombres..." value="<?php echo $name ?>" />
              </div>
              <div class="form-section">
                <label for="">Apellidos:</label>
                <input type="text" name="last_name" placeholder="Ingrese los apellidos..." value="<?php echo $last_name ?>" />
              </div>
              <div class="form-section">
                <label for="">Correo Electronico:</label>
                <input type="email" name="email" placeholder="Ingrese el correo electrónico..." value="<?php echo $email ?>" />
              </div>
              <input class="btn btn-green" type="submit" name="update" value="Actualizar" />
          </div>
        </div>
      </div>
    </div>
    <footer>Copyright 2022</footer>
</body>

</html>