
all:
		echo "sudo python2.7 driver.py $1 --no-log" > rawhttpget && chmod +x rawhttpget
clean:
		rm -rf *.html *.php *.pyc
