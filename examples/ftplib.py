from ftplib import FTP
from ftplib import FTP_TLS


# bad
ftp = FTP('ftp.debian.org')
ftp.login()

ftp.cwd('debian')
ftp.retrlines('LIST')

ftp.quit()

# okay
ftp = ftplib.FTP_TLS(
    "ftp.us.debian.org",
    context=ssl.create_default_context(),
)
ftp.login()

ftp.cwd("debian")
ftp.retrlines("LIST")

ftp.quit()
