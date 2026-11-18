ui_print "****************************************"
ui_print "  HTTP Toolkit Android 14+ Trust Module "
ui_print "****************************************"
ui_print "- Installing module files..."
set_perm_recursive "$MODPATH" 0 0 0755 0644
set_perm "$MODPATH/service.sh" 0 0 0755
set_perm "$MODPATH/post-fs-data.sh" 0 0 0755
ui_print "- Done! Reboot to activate."
