import sys
import boto3
from PyQt5.QtWidgets import *
from PyQt5.QtGui import QPixmap
import os
import shutil
import subprocess

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Malware Detection Tool")
        self.setGeometry(0, 0, 1910, 1040)
        self.initUI()


    def initUI(self):
        pixmap = QPixmap("background.jpeg")
        background_label = QLabel(self)
        background_label.setPixmap(pixmap)
        background_label.setScaledContents(True)
        background_label.setGeometry(0, 0, self.width(), self.height())

        input_button = QPushButton("Take Input", self)
        input_button.move(1350, 300)
        input_button.setStyleSheet("QPushButton{background-color: #000066; color: white; font-size: 24px; padding: 10px 20px; border-radius: 10px; border: 2px solid #000080}"
                                   "QPushButton:hover { background-color: #000033; color: white; }")
        input_button.setFixedSize(200, 60)
        input_button.clicked.connect(self.openFileDialog)

        analyse_button = QPushButton("Analyse", self)
        analyse_button.move(1350, 500)
        analyse_button.setStyleSheet("QPushButton{background-color: #000066; color: white; font-size: 24px; padding: 10px 20px; border-radius: 10px; border: 2px solid #000080}"
                                   "QPushButton:hover { background-color: #000033; color: white; }")
        analyse_button.setFixedSize(200, 60)
    
 
    def openFileDialog(self):
        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog
        filePath, _ = QFileDialog.getOpenFileName(self,"Choose File", "","All Files (*);;Python Files (*.py)", options=options)
        fileName = filePath.split('/')[-1]
        if filePath:
            print(filePath)
            self.label = QLabel(self)
            self.label.setText("File Uploaded.")
            self.label.move(1550, 290)
            self.label.setFixedSize(300, 80)
            self.label.setStyleSheet("color: white; font-size: 18px; padding: 10px 20px;")
            self.label.show()
            global choice
            if(choice == 3):
                self.get_features(filePath)
            elif(choice == 4):
                self.upload_to_s3(filePath, fileName)


    def get_features(self, filePath):
        fileName = filePath.split('/')[-1]
        destination_path = os.getcwd() + "/volatility3"
        shutil.copy(filePath, destination_path)
        os.chdir("./volatility3")
        cmd = "python vol.py -f " + fileName + " windows.pslist > ../output.txt"
        print("Features has been dropped into output.txt")
        subprocess.run(cmd, shell=True)
        os.remove(fileName)

    
    def upload_to_s3(self,file_path,file_name):
        access_key_id = 'AKIA4OE4DMNWJISOMPHM'
        secret_access_key = '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'

        s3 = boto3.client('s3', aws_access_key_id = access_key_id,aws_secret_access_key = secret_access_key)
        response = s3.list_buckets()
        buckets = [bucket['Name'] for bucket in response['Buckets']]
        print("Buckets list : ",buckets)
        bucket_name = buckets[0]
        with open(file_path, 'rb') as f:
            s3.put_object(Bucket=bucket_name, Key=file_name, Body=f)
            print("File " + file_name + " uploaded to s3")
    

def startInstance(instance_id):
    ec2 = boto3.client('ec2')
    instance_id = instance_id
    ec2.start_instances(InstanceIds=[instance_id])
    print("Instance has been started")
        
def stopInstance(instance_id):
    ec2 = boto3.client('ec2')
    instance_id = instance_id
    ec2.stop_instances(InstanceIds=[instance_id])
    print("Instance has been stopped")
        
        
if __name__ == "__main__":
    print("1. Start an instance on aws")
    print("2. Stop an instance on aws")
    print("3. Extract Features by selecting a memory dump.")
    print("4. Upload a file to S3 Bucket")
    choice = int(input("Enter your choice: "))
    if(choice == 1):
        startInstance('i-053134b6a9b7b3772')
    elif(choice == 2):
        stopInstance('i-053134b6a9b7b3772')
    else:
        app = QApplication(sys.argv)
        window = MainWindow()
        window.show()
        sys.exit(app.exec_())


