import pymysql

pymysql.version_info = (1, 4, 13, "final", 0)  # 新版本需要加上，不然报错
pymysql.install_as_MySQLdb()
