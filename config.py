import os
basedir = os.path.abspath(os.path.dirname(__file__))

CSRF_ENABLED = True
SECRET_KEY = '!njKhki@89y79%k;gh#KG&yufrpG:'
DOWNLOAD_DIR = os.path.join(basedir, 'tmp')
LOGFILE = os.path.join(basedir, 'tmp/messages.log')
FILES_DIR = os.path.join(basedir, 'files')

if os.environ.get('DATABASE_URL') is None:
    SQLALCHEMY_DATABASE_URI = ('sqlite:///' + os.path.join(basedir, 'app.db') +
                               '?check_same_thread=False')
else:
    SQLALCHEMY_DATABASE_URI = os.environ['DATABASE_URL']
SQLALCHEMY_MIGRATE_REPO = os.path.join(basedir, 'db_repository')
SQLALCHEMY_RECORD_QUERIES = True

MSG_PER_PAGE = 10
# Max filesize 16 megabytes
MAX_CONTENT_LENGTH = 16 * 1024 * 1024
