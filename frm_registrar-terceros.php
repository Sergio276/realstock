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
  <script src="https://cdn.jsdelivr.net/npm/jquery@3.6.0/dist/jquery.slim.min.js"></script>
  <link href="https://fonts.googleapis.com/css2?family=Josefin+Sans:wght@300&display=swap" rel="stylesheet" />
  <script defer src="https://kit.fontawesome.com/707789a0bc.js" crossorigin="anonymous"></script>
  <script defer src="js/script.js"></script>
</head>

<body>
  <nav>
    <div class="logo">
      <a href="principal.php"><img src="img/logo.png" alt="" /></a>
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
          <a href="principal.php"><i class="fa-solid fa-house-chimney"></i> Inicio /</a> Inventarios /
          Terceros
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
        <div class="search-group">
          <input class="search-bar" placeholder="Buscar tercero..." />
          <button class="icon-search">
            <i class="fa-solid fa-magnifying-glass"></i>
          </button>
        </div>
        <button class="btn btn-green" data-btn-modal="true" data-modal="#m-registrar-tercero">Registar
          Tercero</button>
        <div class="modal-wrapper" id="m-registrar-tercero">
          <div class="modal">
            <div class="modal-header">
              <div>Registar Tercero</div>
              <i class="fa-solid fa-xmark" data-btn-close="modal"></i>
            </div>
            <div class="modal-content">
              <form action="./php/add-third.php" method="post" autocomplete="off">
                <div class="form-section">
                  <label for="">Tipo de documento:</label>
                  <select required name="document_type">
                    <option value="">Seleccione el tipo de documento</option>
                    <option value="CC">Cédula de ciudadanía</option>
                    <option value="CE">Cédula de extranjería</option>
                    <option value="NIT">Número de identificación tributaria</option>
                    <option value="TI">Tarjeta de identidad</option>
                    <option value="PAP">Pasaporte</option>
                  </select>
                </div>
                <div class="form-section">
                  <label for="">No. de documento:</label>
                  <input type="text" required name="document" placeholder="Ingrese el No. de documento">
                </div>
                <div class="form-section">
                  <label for="">Razón social:</label>
                  <input type="text" required name="business_name" placeholder="Ingrese la razón social">
                </div>
                <div class="form-section">
                  <label for="">Estado:</label>
                  <input type="text" required name="status" placeholder="Ingrese el estado">
                </div>
                <div class="form-section">
                  <label for="">Nombre de contacto:</label>
                  <input type="text" required name="contact_name" placeholder="Ingrese el nombre de contacto">
                </div>
                <div class="form-section">
                  <label for="">Teléfono:</label>
                  <input type="text" required name="phone" placeholder="Ingrese el teléfono">
                </div>
                <div class="form-section">
                  <label for="">Página web:</label>
                  <input type="text" name="web_page" placeholder="Ingrese la página web">
                </div>
                <div class="form-section">
                  <label for="">Email:</label>
                  <input type="email" name="email" placeholder="Ingrese el email">
                </div>
                <div class="form-section">
                  <label for="">Departamento:</label>
                  <input type="text" required name="department" placeholder="Ingrese el departamento">
                </div>
                <div class="form-section">
                  <label for="">Ciudad:</label>
                  <input type="text" required name="city" placeholder="Ingrese la ciudad">
                </div>
                <div class="form-section">
                  <label for="">Dirección:</label>
                  <input type="text" required name="address" placeholder="Ingrese la dirección">
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
            <th colspan="17">Terceros</th>
          </tr>
          <tr class="titles-table">
            <td class="cell-center">Id</td>
            <td>Tipo de documento</td>
            <td>No. Documento</td>
            <td>Razón social</td>
            <td>Estado</td>
            <td>Nombre de contacto</td>
            <td>Teléfono</td>
            <td>Pagina web</td>
            <td>Email</td>
            <td>Departamento</td>
            <td>Ciudad</td>
            <td>Dirección</td>
            <td class="cell-center">Eliminar</td>
            <td class="cell-center">Editar</td>
          </tr>
          <tbody id="content-table">
            <?php
            include_once './php/config.php';

            $query = "SELECT * FROM tbl_tercero";

            $result = mysqli_query($conn, $query);

            if ($result) {
              if (mysqli_num_rows($result) > 0) {
                foreach ($result as $row) {
            ?>
                  <tr>
                    <td class="cell-center"><?php echo $row['tercero_id'] ?></td>
                    <td><?php echo $row['tipo_de_documento'] ?></td>
                    <td><?php echo $row['no_documento'] ?></td>
                    <td><?php echo $row['razon_social'] ?></td>
                    <td><?php echo $row['estado'] ?></td>
                    <td><?php echo $row['nombre_contacto'] ?></td>
                    <td><?php echo $row['telefono'] ?></td>
                    <td><?php echo $row['pagina_web'] ?></td>
                    <td><?php echo $row['email'] ?></td>
                    <td><?php echo $row['departamento'] ?></td>
                    <td><?php echo $row['ciudad'] ?></td>
                    <td><?php echo $row['direccion'] ?></td>
                    <td class="cell-center">
                      <div data-btn-modal="true" data-modal="#m-eliminar-rol_<?php echo $row['tercero_id'] ?>"><img src="img/delete.png" alt="" />
                      </div>
                    </td>
                    <td class="cell-center">
                      <div title="Editar" data-btn-modal="true" data-modal="#m-editar-tercero_<?php echo $row['tercero_id'] ?>"><img src="img/editar.png" alt="Editar" /></div>
                    </td>
                  </tr>

                  <div class="modal-wrapper" id="m-eliminar-rol_<?php echo $row['tercero_id'] ?>">
                    <div class="modal">
                      <div class="modal-header">
                        <div>Eliminar información del tercero</div>
                        <i class="fa-solid fa-xmark" data-btn-close="modal"></i>
                      </div>
                      <div class="modal-content">
                        <h2>¿Está seguro de eliminar a “<?php echo $row['nombre_contacto'] ?>”?</h2>
                        <div class="options-delete">
                          <a href="./php/delete-third.php?third_id=<?php echo $row['tercero_id'] ?>" class="btn btn-red">Eliminar</a>
                          <button class="btn btn-gray" data-btn-cancel="modal">Cancelar</button>
                        </div>
                      </div>
                    </div>
                  </div>
                  <div class="modal-wrapper" id="m-editar-tercero_<?php echo $row['tercero_id'] ?>">
                    <div class="modal">
                      <div class="modal-header">
                        <div>Editar información del tercero</div>
                        <i class="fa-solid fa-xmark" data-btn-close="modal"></i>
                      </div>
                      <div class="modal-content">
                        <form action="./php/update-third.php?third_id=<?php echo $row['tercero_id'] ?>" method="post">
                          <div class="form-section">
                            <label for="">Tipo de documento:</label>
                            <?php
                            switch ($row['tipo_de_documento']) {
                              case 'CC':
                            ?>
                                <select name="document_type">
                                  <option value="">Seleccione el tipo de documento</option>
                                  <option selected value="CC">Cédula de ciudadanía</option>
                                  <option value="CE">Cédula de extranjería</option>
                                  <option value="NIT">Número de identificación tributaria</option>
                                  <option value="TI">Tarjeta de identidad</option>
                                  <option value="PAP">Pasaporte</option>
                                </select>
                              <?php
                                break;
                              case 'CE':
                              ?>
                                <select name="document_type">
                                  <option value="">Seleccione el tipo de documento</option>
                                  <option value="CC">Cédula de ciudadanía</option>
                                  <option selected value="CE">Cédula de extranjería</option>
                                  <option value="NIT">Número de identificación tributaria</option>
                                  <option value="TI">Tarjeta de identidad</option>
                                  <option value="PAP">Pasaporte</option>
                                </select>
                              <?php
                                break;
                              case 'NIT':
                              ?>
                                <select name="document_type">
                                  <option value="">Seleccione el tipo de documento</option>
                                  <option value="CC">Cédula de ciudadanía</option>
                                  <option value="CE">Cédula de extranjería</option>
                                  <option selected value="NIT">Número de identificación tributaria</option>
                                  <option value="TI">Tarjeta de identidad</option>
                                  <option value="PAP">Pasaporte</option>
                                </select>
                              <?php
                                break;
                              case 'TI':
                              ?>
                                <select name="document_type">
                                  <option value="">Seleccione el tipo de documento</option>
                                  <option value="CC">Cédula de ciudadanía</option>
                                  <option value="CE">Cédula de extranjería</option>
                                  <option value="NIT">Número de identificación tributaria</option>
                                  <option selected value="TI">Tarjeta de identidad</option>
                                  <option value="PAP">Pasaporte</option>
                                </select>
                              <?php
                                break;
                              case 'PAP':
                              ?>
                                <select name="document_type">
                                  <option value="">Seleccione el tipo de documento</option>
                                  <option value="CC">Cédula de ciudadanía</option>
                                  <option value="CE">Cédula de extranjería</option>
                                  <option value="NIT">Número de identificación tributaria</option>
                                  <option value="TI">Tarjeta de identidad</option>
                                  <option selected value="PAP">Pasaporte</option>
                                </select>
                              <?php
                                break;
                              default:
                              ?>
                                <input type="text" disabled value="No se encontró el tipo de documento">
                            <?php
                                break;
                            }
                            ?>
                          </div>
                          <div class="form-section">
                            <label for="">No. de documento:</label>
                            <input type="text" name="document" value="<?php echo $row['no_documento'] ?>" placeholder="Ingrese el No. de documento">
                          </div>
                          <div class="form-section">
                            <label for="">Razón social:</label>
                            <input type="text" name="business_name" value="<?php echo $row['razon_social'] ?>" placeholder="Ingrese la razón social">
                          </div>
                          <div class="form-section">
                            <label for="">Estado:</label>
                            <input type="text" name="status" value="<?php echo $row['estado'] ?>" placeholder="Ingrese el estado">
                          </div>
                          <div class="form-section">
                            <label for="">Nombre de contacto:</label>
                            <input type="text" name="contact_name" value="<?php echo $row['nombre_contacto'] ?>" placeholder="Ingrese el nombre de contacto">
                          </div>
                          <div class="form-section">
                            <label for="">Teléfono:</label>
                            <input type="text" name="phone" value="<?php echo $row['telefono'] ?>" placeholder="Ingrese el teléfono">
                          </div>
                          <div class="form-section">
                            <label for="">Página web:</label>
                            <input type="text" name="web_page" value="<?php echo $row['pagina_web'] ?>" placeholder="Ingrese la página web">
                          </div>
                          <div class="form-section">
                            <label for="">Email:</label>
                            <input type="email" name="email" value="<?php echo $row['email'] ?>" placeholder="Ingrese el email">
                          </div>
                          <div class="form-section">
                            <label for="">Departamento:</label>
                            <input type="text" name="department" value="<?php echo $row['departamento'] ?>" placeholder="Ingrese el departamento">
                          </div>
                          <div class="form-section">
                            <label for="">Ciudad:</label>
                            <input type="text" name="city" value="<?php echo $row['ciudad'] ?>" placeholder="Ingrese la ciudad">
                          </div>
                          <div class="form-section">
                            <label for="">Dirección:</label>
                            <input type="text" name="address" value="<?php echo $row['direccion'] ?>" placeholder="Ingrese la dirección">
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
              alert("No se encontraron terceros registrados");
              </script>';
              }
            } else {
              echo '<script type="text/javascript">
            alert("Error al consultar a terceros");
            </script>';
            }
            ?>
          </tbody>
        </table>
      </div>
    </div>
    <footer>Copyright 2022</footer>
  </div>

</body>

</html