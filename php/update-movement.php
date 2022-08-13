<?php
if (isset($_POST['update'], $_GET['movement_id'])) {
    require 'config.php';

    $type_movement = $_POST['type_movement'];
    $subtype_movement = $_POST['subtype_movement'];
    $amount = $_POST['amount'];
    $unit_cost = $_POST['unit_cost'];
    $description = $_POST['description'];
    $product = $_POST['product'];
    $third = $_POST['third'];

    $movement_id = $_GET['movement_id'];

    $stmt = $conn->prepare("UPDATE tbl_movimiento SET tipo_movimiento = ?, subtipo_movimiento = ?, cantidad = ?, costo_unitario = ?, descripcion = ?, tbl_producto_id = ?, tbl_tercero_id = ? WHERE movimiento_id = ?");
    $stmt->bind_param('ssssssss', $type_movement, $subtype_movement, $amount, $unit_cost, $description, $product, $third, $movement_id);

    $stmt->execute();
    if (($stmt) && ($stmt->affected_rows == 1)) {
        echo '<script type="text/javascript">
        alert("Se actualizó correctamente el movimiento: ' . $type_movement . '");
        window.location.href = "../frm_registrar-movimientos.php";
        </script>';
    } else {
        echo '<script type="text/javascript">
        alert("Error al actualizar el movimiento");
        window.location.href = "../frm_registrar-movimientos.php";
        </script>';
    }
    $stmt->close();
    $conn->close();
}
