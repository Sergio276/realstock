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
  <script src="https://cdn.jsdelivr.net/npm/jquery@3.6.0/dist/jquery.slim.min.js"></script>
  <script defer src="https://kit.fontawesome.com/707789a0bc.js" crossorigin="anonymous"></script>
  <script defer src="js/script.js"></script>
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
          <a href="#">
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
          <a href="principal.php"><i class="fa-solid fa-house-chimney"></i> Inicio</a>
          / Usuarios
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
      <div class="items-container">
        <a href="frm_crear-roles.php" class="btn btn-blue">Roles</a>
        <div class="search-group">
          <input class="search-bar" name="data" type="text" placeholder="Buscar usuario..." />
          <button class="icon-search">
            <i class="fa-solid fa-magnifying-glass"></i>
          </button>
        </div>
        <button class="btn btn-green" data-btn-modal="true" data-modal="#m-registrar-usuario">Registrar</button>
        <div class="modal-wrapper" id="m-registrar-usuario">
          <div class="modal">
            <div class="modal-header">
              <div>Registrar usuario</div>
              <i class="fa-solid fa-xmark" data-btn-close="modal"></i>
            </div>
            <div class="modal-content">
              <form action="php/add-user.php" method="post">
                <div class="form-section">
                  <label for="">Usuario:</label>
                  <input type="text" name="user" required placeholder="Ingrese el nombre de usuario..." />
                </div>
                <div class="form-section">
                  <label for="">Contraseña:</label>
                  <input type="password" minlength="8" name="password" required placeholder="Ingrese la contraseña..." />
                </div>
                <div class="form-section">
                  <label for="">Confirmar contraseña:</label>
                  <input type="password" minlength="8" name="confirm_pass" required placeholder="Confirme la contraseña..." />
                </div>
                <div class="form-section">
                  <label for="">Email:</label>
                  <input type="email" name="email" required placeholder="Ingrese el email..." />
                </div>
                <div class="form-section">
                  <label for="">Nombres:</label>
                  <input type="text" name="name" required placeholder="Ingrese nombre..." />
                </div>
                <div class="form-section">
                  <label for="">Apellidos:</label>
                  <input type="text" name="last_name" required placeholder="Ingrese apellidos..." />
                </div>
                <div class="form-section">
                  <label for="">Estado</label>
                  <select name="status" required>
                    <option value="">Seleccione el estado del usuario</option>
                    <option value="activo">Activo</option>
                    <option value="desactivo">Desactivo</option>
                  </select>
                </div>
                <input class="btn btn-green" type="submit" name="register" value="Registrar" />
              </form>
            </div>
          </div>
        </div>
      </div>
      <div class="wrapper-table">
        <table>
          <tr>
            <th colspan="8">Usuarios</th>
          </tr>
          <tr class="titles-table">
            <td class="cell-center">Id</td>
            <td>Usuario</td>
            <td>Email</td>
            <td>Nombres</td>
            <td>Apellidos</td>
            <td class="cell-center">Estado</td>
            <td class="cell-center">Editar</td>
            <td class="cell-center">Asignar</td>
          </tr>
          <tbody id="content-table">
            <?php
            include_once 'php/config.php';
            $query = "SELECT * FROM tbl_usuario";
            $result = mysqli_query($conn, $query);

            if ($result) {
              if (mysqli_num_rows($result) > 0) {
                foreach ($result as $row) {
            ?>
                  <tr>
                    <td class="cell-center"><?php echo $row['usuario_id'] ?></td>
                    <td><?php echo $row['usuario'] ?></td>
                    <td><?php echo $row['email'] ?></td>
                    <td><?php echo $row['nombres'] ?></td>
                    <td><?php echo $row['apellidos'] ?></td>
                    <?php
                    if ($row['estado'] == "activo") {
                      $status_img = "aceptar.png";
                    } else {
                      $status_img = "cancelar.png";
                    }
                    ?>
                    <td class="cell-center"><img src="img/<?php echo $status_img ?>" alt="" /></td>
                    <td class="cell-center">
                      <div title="Editar" data-btn-modal="true" data-modal="#m-editar-usuario_<?php echo $row['usuario_id'] ?>"><img src="img/editar.png" alt="Editar" /></div>
                    </td>
                    <td class="cell-center">
                      <button class="btn btn-purple" data-btn-modal="true" data-modal="#m-asignar-rol">
                        <i class="fa-solid fa-unlock-keyhole"></i>Asignar rol
                      </button>
                    </td>
                  </tr>

                  <div class="modal-wrapper" id="m-editar-usuario_<?php echo $row['usuario_id'] ?>">
                    <div class="modal">
                      <div class="modal-header">
                        <div>Editar información de usuario</div>
                        <i class="fa-solid fa-xmark" data-btn-close="modal"></i>
                      </div>
                      <div class="modal-content">
                        <form action="./php/update-user.php?user_id=<?php echo $row['usuario_id'] ?>" method="post">
                          <div class="form-section">
                            <label for="">Usuario:</label>
                            <input type="text" placeholder="Ingrese el nombre de usuario..." name="user" value="<?php echo $row['usuario'] ?>" />
                          </div>
                          <div class="form-section">
                            <label for="">Contraseña:</label>
                            <input type="password" minlength="8" placeholder="Ingrese la contraseña..." name="password" value="" />
                          </div>
                          <div class="form-section">
                            <label for="">Confirmar contraseña:</label>
                            <input type="password" minlength="8" placeholder="Confirme la contraseña..." name="confirm_pass" value="" />
                          </div>
                          <div class="form-section">
                            <label for="">Email:</label>
                            <input type="email" placeholder="Ingrese el email..." name="email" value="<?php echo $row['email'] ?>" />
                          </div>
                          <div class="form-section">
                            <label for="">Nombres:</label>
                            <input type="text" placeholder="Ingrese nombre..." name="name" value="<?php echo $row['nombres'] ?>" />
                          </div>
                          <div class="form-section">
                            <label for="">Apellidos:</label>
                            <input type="text" placeholder="Ingrese apellidos..." name="last_name" value="<?php echo $row['apellidos'] ?>" />
                          </div>
                          <div class="form-section">
                            <label for="">Estado:</label>
                            <select name="status" required>
                              <?php
                              if ($row['estado'] == "activo") {
                              ?>
                                <option value="">Seleccione el estado del usuario</option>
                                <option value="activo" selected>Activo</option>
                                <option value="desactivo">Desactivo</option>
                              <?php
                              } else {
                              ?>
                                <option value="">Seleccione el estado del usuario</option>
                                <option value="activo">Activo</option>
                                <option value="desactivo" selected>Desactivo</option>
                              <?php
                              }
                              ?>
                            </select>
                          </div>
                          <input class="btn btn-green submit" type="submit" name="update" value="Actualizar" />
                        </form>
                      </div>
                    </div>
                  </div>
            <?php
                }
              } else {
                echo '<script type="text/javascript">
                alert("No se encontraron usuarios registrados");
                </script>';
              }
            } else {
              echo '<script type="text/javascript">
              alert("Error al consultar la lista de usuarios");
              </script>';
            }

            ?>
          </tbody>
        </table>
      </div>
    </div>
    <footer>Copyright 2022</footer>
  </div>

  <div class="modal-wrapper" id="m-asignar-rol">
    <div class="modal">
      <div class="modal-header">
        <div>Asignar rol</div>
        <i class="fa-solid fa-xmark" data-btn-close="modal"></i>
      </div>
      <div class="modal-content">
        <form action="#">
          <div class="form-section">
            <label for="">Rol:</label>
            <select>
              <option value="" selected>Seleccione el rol</option>
              <option value="Super administrador">Super administrador</option>
              <option value="Administrador">Administrador</option>
              <option value="Usuario">Usuario</option>
            </select>
          </div>
          <input class="btn btn-green" type="submit" value="Asignar" />
        </form>
      </div>
    </div>
  </div>
</body>

</html>