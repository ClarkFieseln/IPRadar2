import shlex,  subprocess

print("Updating requirements.txt..")
p1 = subprocess.Popen(shlex.split("pipreqs --force ./ --ignore backups"), shell=True)
p1.wait()
p1.terminate()
p1.kill()




                
