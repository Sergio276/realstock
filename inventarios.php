<?php
require_once './php/session-data.php';
?>
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
          <a href="./frm_registrar-usuarios.php">
            <i class="fa-solid fa-user-group"></i> Usuarios
          </a>
        </li>
        <li class="link">
          <a href="#">
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
          <a href="principal.php" title="Inicio"><i class="fa-solid fa-house-chimney"></i> Inicio </a> / Inventarios
        </div>
      </div>
      <div class="section-header">
        <div class="user-tag">
          <a href="frm_editar-perfil.php"><i class="fa-solid fa-circle-user"></i><?php echo $_SESSION['username'] ?></a>
        </div>
        <div class="btn-logout">
          <a href="./php/logout.php"><i class="fa-solid fa-right-from-bracket"></i></a>
        </div>
      </div>
    </header>
    <div class="content">
      <div class="cards-container">
        <div class="card">
          <a href="frm_registrar-movimientos.php">
            <div class="card-content">
              <div class="icono">
                <img src="img/inventory.svg" alt="" />
              </div>
              <div class="text">Movimientos</div>
            </div>
          </a>
        </div>
        <div class="card">
          <a href="frm_registrar-terceros.php">
            <div class="card-content">
              <div class="icono">
                <img src="img/relacion-de-usuarios.svg" alt="" />
              </div>
              <div class="text">Terceros</div>
            </div>
          </a>
        </div>
        <div class="card">
          <a href="frm_registrar-productos.php">
            <div class="card-content">
              <div class="icono">
                <img src="img/producto.svg" alt="" />
              </div>
              <div class="text">Productos</div>
            </div>
          </a>
        </div>
        <div class="card">
          <a href="frm_crear-categorias.php">
            <div class="card-content">
              <div class="icono">
                <img src="img/categorizacion.svg" alt="" />
              </div>
              <div class="text">Categorías</div>
            </div>
          </a>
        </div>
        <div class="card">
          <a href="frm_crear-subcategorias.php">
            <div class="card-content">
              <div class="icono">
                <img src="img/lineas-de-opciones.svg" alt="" />
              </div>
              <div class="text">Subcategorías</div>
            </div>
          </a>
        </div>
      </div>
    </div>
    <footer>Copyright 2022</footer>
  </div>
</body>

</html>