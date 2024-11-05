import sys
import os
import re
import paho.mqtt.client as mqtt
from PyQt5 import QtWidgets, QtGui, QtCore
from PyQt5.QtCore import QTimer

from PyQt5.QtGui import QSyntaxHighlighter, QTextCharFormat, QColor
from PyQt5.QtCore import Qt, QRegExp

frame_fname = '../tmp/frame.txt' 
regs_fname = '../tmp/regs.txt'
pc_file_path = '/tmp/pc.txt'
mqtt_broker = '127.0.0.1'
mqtt_topic = 'asm/pc'

class AssemblySyntaxHighlighter(QSyntaxHighlighter):
    def __init__(self, document):
        super().__init__(document)
        self.highlighting_rules = []

        # Define formats for different components
        address_format = QTextCharFormat()
        address_format.setForeground(QColor("cyan"))

        mnemonic_format = QTextCharFormat()
        mnemonic_format.setForeground(QColor("yellow"))

        register_format = QTextCharFormat()
        register_format.setForeground(QColor("green"))

        # Define highlighting rules
        address_pattern = QRegExp(r'\b0x[0-9a-fA-F]+\b')
        self.highlighting_rules.append((address_pattern, address_format))

        mnemonic_pattern = QRegExp(r'\b(?:add|tbz|cs|ldrsw|sub|mul|udiv|sdiv|orr|eor|and|bic|mov|mvn|ldr|str|ldp|stp|ldrb|strb|ldrh|strh|ldrsb|ldrsh|b|bl|br|bx|cbz|cbnz|cmp|cmn|lsl|lsr|asr|rev|rbit|nop|svc)\b')
        self.highlighting_rules.append((mnemonic_pattern, mnemonic_format))

        register_pattern = QRegExp(r'\b(?:[xws][0-9]+)\b')
        self.highlighting_rules.append((register_pattern, register_format))

    def highlightBlock(self, text):
        for pattern, fmt in self.highlighting_rules:
            index = pattern.indexIn(text)
            while index >= 0:
                length = pattern.matchedLength()
                self.setFormat(index, length, fmt)
                index = pattern.indexIn(text, index + length)

class DisassemblyWindow(QtWidgets.QWidget):
    # Define a signal to update disassembly
    update_disassembly_signal = QtCore.pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.initUI()
        
        # Initialize MQTT client
        self.mqtt_client = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION2)
        self.mqtt_client.on_connect = self.on_connect
        self.mqtt_client.on_message = self.on_message

        # Connect to the MQTT broker
        self.mqtt_client.connect(mqtt_broker)

        # Connect the signal to the slot
        self.update_disassembly_signal.connect(self.update_disassembly_from_signal)

        # Start the MQTT loop in a separate thread
        self.mqtt_client.loop_start()

        self.setupASM()
        self.last_pc = ''

    def initUI(self):
        self.setWindowTitle('GDB Disassembly viewer <q> to quit')
        self.setGeometry(100, 100, 580, 900)

        # Set dark theme stylesheet
        self.setStyleSheet("""
            QWidget {
                background-color: #2E2E2E;
                color: #FFFFFF;
            }
            QTextEdit {
                background-color: #1E1E1E;
                color: #FFFFFF;
                border: 1px solid #444444;
            }
        """)        
        
        self.textEdit = QtWidgets.QTextEdit(self)
        self.textEdit.setReadOnly(True)

        font = QtGui.QFont("Hack Nerd Font", 12)
        self.textEdit.setFont(font)        
        
        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(self.textEdit)

        footer_layout = QtWidgets.QHBoxLayout()

        button = QtWidgets.QPushButton('refresh', self)
        footer_layout.addWidget(button)

        button.clicked.connect(self.on_refresh_clicked)

        layout.addLayout(footer_layout)
        
        self.setLayout(layout)
        
        self.highlighter = AssemblySyntaxHighlighter(self.textEdit.document())        

    def on_refresh_clicked(self):
        self.update_disassembly_from_signal('refresh')

    def setupASM(self):
        """Load initial disassembly and subscribe to MQTT topic."""
        try:
            with open(frame_fname, 'r') as f:
                disassembly = f.read()
                self.textEdit.setPlainText(disassembly)  # Set initial content
                
                # Subscribe to the MQTT topic after loading initial disassembly
                self.mqtt_client.subscribe(mqtt_topic)
                print("Subscribed to MQTT topic:", mqtt_topic)
                
        except Exception as e:
            print(f"Error loading initial disassembly: {e}")

    def keyPressEvent(self, event):
      """Handle key press events."""
      if event.key() == Qt.Key_Q:  # Check if 'Q' is pressed
          self.close()  # Close the application

    def on_connect(self, client, userdata, flags, reason_code, properties):
      print(f"Connected to MQTT broker with result code {reason_code}")

    def on_message(self, client, userdata, msg):
      print(f"Message received on topic {msg.topic}: {msg.payload.decode()}")
      new_disassembly = msg.payload.decode()
      if new_disassembly:
          # Emit signal with new disassembly data for safe UI update
          self.update_disassembly_signal.emit(new_disassembly)

    def update_disassembly_from_signal(self, new_disassembly):
      """Slot to update disassembly safely from the main thread."""
      footer = ''
      full_asm = ''
      if len(self.last_pc) > 0:
          footer = f'lastpc: {self.last_pc}'

      try:
          with open(frame_fname, 'r') as f:
              disassembly = f.read()
              full_asm = disassembly + '\n' + footer

              with open(regs_fname, 'r') as f:
                  reg_values = f.read()
              full_asm = disassembly + '\n' + footer + '\n' + reg_values + '\n'

      except Exception as e:
          print(f"Error updating disassembly: {e}")

      self.textEdit.setPlainText(full_asm)

def main():
    app = QtWidgets.QApplication(sys.argv)
    window = DisassemblyWindow()
    window.show()
    
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
