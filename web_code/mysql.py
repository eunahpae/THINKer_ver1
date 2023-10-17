import pymysql
from passlib.hash import pbkdf2_sha256

def hash_password(original_password):
    salt = 'eungok'
    password = original_password + salt
    password = pbkdf2_sha256.hash(password)
    return password
def check_password(input_password, hashed_password):
    salt = 'eungok'
    password=input_password + salt
    result=pbkdf2_sha256.verify(password, hashed_password)
    return result

class Mysql:
    def __init__(self, host='EunahPae.mysql.pythonanywhere-services.com', user='EunahPae', db='EunahPae$THINKer_in', password='', charset='utf8'):
        self.host = host
        self.user = user
        self.db = db
        self.password = password
        self.charset = charset

    def connect(self):
        return pymysql.connect(host=self.host, user=self.user, db=self.db, password=self.password, charset=self.charset)

    def execute_sql(self, sql, *args):
        db = self.connect()
        with db.cursor() as curs:
            result = curs.execute(sql, args)
            db.commit()
        db.close()
        return result

    def get_user(self):
        sql = "SELECT * FROM user;"
        with self.connect().cursor() as curs:
            curs.execute(sql)
            rows = curs.fetchall()
        return rows

    def social_check(self, social_name, social_email, social_phone, social_password):
        sql = "SELECT * FROM user WHERE email = %s"
        with self.connect().cursor() as curs:
            curs.execute(sql, (social_email,))
            rows = curs.fetchall()

        if rows:
            return "이미 존재하는 이메일입니다"
        else:
            sql = "INSERT INTO user (username, email, phone, password) VALUES (%s, %s, %s, %s)"
            return self.execute_sql(sql, social_name, social_email, social_phone, social_password)

    def verify_password(self, password, hashed_password):
        return check_password(password, hashed_password)

    def additional_info(self, email, phone):
        db = pymysql.connect(host=self.host, user=self.user, db=self.db, password=self.password, charset=self.charset)
        curs = db.cursor()
        sql = ''' UPDATE user SET phone =%s WHERE email =%s'''
        curs.execute(sql,(phone, email))
        db.commit()
        db.close()

    def insert_user(self, username, email, phone, password):
        hashed_password = hash_password(password)
        sql = "INSERT INTO user (username, email, phone, password) VALUES (%s, %s, %s, %s)"
        return self.execute_sql(sql, username, email, phone, hashed_password)

    def del_user(self, email):
        sql = "DELETE FROM user WHERE email = %s"
        return self.execute_sql(sql, email)
