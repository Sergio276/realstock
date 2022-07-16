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
      <a href="principal.html"><img src="img/logo.png" alt="" /></a>
    </div>
    <div class="links">
      <ul>
        <li class="link">
          <a href="principal.html">
            <i class="fa-solid fa-house-chimney"></i> Inicio
          </a>
        </li>
        <li class="link">
          <a href="frm_registrar-usuarios.php">
            <i class="fa-solid fa-user-group"></i> Usuarios
          </a>
        </li>
        <li class="link">
          <a href="inventarios.html">
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
          <a href="principal.html"><i class="fa-solid fa-house-chimney"></i> Inicio /</a>
          <a href="frm_registrar-usuarios.html">Usuarios / </a> Roles
        </div>
      </div>
      <div class="section-header">
        <div class="user-tag">
          <a href="frm_editar-perfil.html"><i class="fa-solid fa-circle-user"></i>Usuario</a>
        </div>
        <div class="btn-logout">
          <a href="index.html"><i class="fa-solid fa-right-from-bracket"></i></a>
        </div>
      </div>
    </header>
    <div class="content">
      <div class="items-container">
        <div class="search-bar">
          <div class="icon-search">
            <i class="fa-solid fa-magnifying-glass"></i>
          </div>
          <input type="text" placeholder="Buscar rol..." />
        </div>
        <button class="btn btn-green" data-btn-modal="true" data-modal="#m-crear-rol">Crear nuevo rol</button>
        <div class="modal-wrapper" id="m-crear-rol">
          <div class="modal">
            <div class="modal-header">
              <div>Crear nuevo rol</div>
              <i class="fa-solid fa-xmark" data-btn-close="modal"></i>
            </div>
            <div class="modal-content">
              <form action="php/add-rol.php" method="post">
                <div class="form-section">
                  <label for="">Nombre del rol:</label>
                  <input type="text" required name="rol" placeholder="Ingrese el nombre del rol..." />
                </div>
                <div class="form-section">
                  Añadir permisos:
                  <select required name="permissions[]">
                    <option value="">Seleccione el permiso</option>
                    <option value="usuarios">Usuarios</option>
                    <option value="inventarios">Inventarios</option>
                  </select>
                  <select name="permissions[]">
                    <option value="">Seleccione el permiso</option>
                    <option value="usuarios">Usuarios</option>
                    <option value="inventarios">Inventarios</option>
                  </select>
                </div>
                <input class="btn btn-green" type="submit" name="save" value="Guardar" />
              </form>
            </div>
          </div>
        </div>
      </div>
      <div class="wrapper-table">
        <table>
          <tr>
            <th colspan="8">Roles</th>
          </tr>
          <tr class="titles-table">
            <td class="cell-center">Id</td>
            <td>Nombre del rol</td>
            <td>Permisos</td>
            <td class="cell-center">Eliminar</td>
            <td class="cell-center">Editar</td>
          </tr>
          <?php
          include_once 'php/config.php';
          $query = "SELECT * FROM tbl_rol";
          $result = mysqli_query($conn, $query);

          if ($result == true) {
            if (mysqli_num_rows($result) > 0) {
              foreach ($result as $row) {
          ?>
                <tr>
                  <td class="cell-center"><?php echo $row['rol_id'] ?></td>
                  <td><?php echo $row['nombre'] ?></td>
                  <td><?php echo $row['permisos'] ?></td>
                  <td class="cell-center">
                    <div data-btn-modal="true" data-modal="#m-eliminar-rol_<?php echo $row['rol_id'] ?>"><img src="img/delete.png" alt="" /></div>
                  </td>
                  <td class="cell-center">
                    <div title="Editar" data-btn-modal="true" data-modal="#m-editar-rol_<?php echo $row['rol_id'] ?>"><img src="img/editar.png" alt="Editar" /></div>
                  </td>
                </tr>

                <div class="modal-wrapper" id="m-eliminar-rol_<?php echo $row['rol_id'] ?>">
                  <div class="modal">
                    <div class="modal-header">
                      <div>Eliminar rol</div>
                      <i class="fa-solid fa-xmark" data-btn-close="modal"></i>
                    </div>
                    <div class="modal-content">
                      <h2>¿Está seguro de eliminar “<?php echo $row['nombre'] ?>”?</h2>
                      <div class="options-delete">
                        <button class="btn btn-red">Eliminar</button>
                        <button class="btn btn-gray" data-btn-cancel="modal">Cancelar</button>
                      </div>
                    </div>
                  </div>
                </div>

                <div class="modal-wrapper" id="m-editar-rol_<?php echo $row['rol_id'] ?>">
                  <div class="modal">
                    <div class="modal-header">
                      <div>Editar rol</div>
                      <i class="fa-solid fa-xmark" data-btn-close="modal"></i>
                    </div>
                    <div class="modal-content">
                      <form action="php/update-rol.php?rol_id=<?php echo $row['rol_id'] ?>" method="post">
                        <div class="form-section">
                          <label for="">Nombre del rol:</label>
                          <input type="text" name="rol" placeholder="Ingrese el nombre del rol..." value="<?php echo $row['nombre'] ?>" />
                        </div>
                        <div class="form-section">
                          Añadir permisos:
                          <select required name="permissions[]">
                            <option value="">Seleccione el permiso</option>
                            <option value="usuarios">Usuarios</option>
                            <option value="inventarios">Inventarios</option>
                          </select>
                          <select name="permissions[]">
                            <option value="">Seleccione el permiso</option>
                            <option value="usuarios">Usuarios</option>
                            <option value="inventarios">Inventarios</option>
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
                alert("No se encontraron roles registrados");
                </script>';
            }
          } else {
            echo '<script type="text/javascript">
              alert("Error al consultar la lista de roles");
              </script>';
          }

          ?>
        </table>
      </div>
    </div>
    <footer>Copyright 2022</footer>
  </div>
</body>

</html>