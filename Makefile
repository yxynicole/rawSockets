
all:
		echo "sudo python2.7 driver.py \$$@" > rawhttpget && chmod +x rawhttpget
clean:
		rm -rf *.html *.php *.pyc
