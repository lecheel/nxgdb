import sys
import re
from PyQt5.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QWidget, QMessageBox, QCheckBox, QPushButton
from PyQt5.QtCore import Qt, QRegExp

class CheatManager(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Cheat Manager")
        self.setGeometry(100, 100, 400, 300)

        self.cheats = []
        self.load_cheats()

        self.init_ui()
        self.apply_dark_theme()  # Apply dark theme

    def init_ui(self):
        layout = QVBoxLayout()

        self.checkboxes = []  # Store checkbox references

        for idx, (name, _) in enumerate(self.cheats):
            checkbox = QCheckBox(name)
            checkbox.setChecked(False)  # Initially unchecked
            self.checkboxes.append((checkbox, idx))  # Store the checkbox and its index
            layout.addWidget(checkbox)

        self.enable_button = QPushButton("Enable Selected Cheats")
        self.enable_button.clicked.connect(self.enable_selected_cheats)

        layout.addWidget(self.enable_button)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)


    def keyPressEvent(self, event):
      """Handle key press events."""
      if event.key() == Qt.Key_Q:  # Check if 'Q' is pressed
          self.close()  # Close the application


    def load_cheats(self):
        cheat_id = "C8CA2B28323A276B"
        file_path = f"./{cheat_id.upper()}.txt"

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
                current_cheat_name = None
                current_values = []

                for line in lines:
                    line = line.strip()
                    if not line:
                        continue
                    
                    cheat_name_match = re.search(r'\[(.*?)\]', line)
                    if cheat_name_match:
                        if current_cheat_name:
                            self.cheats.append((current_cheat_name, current_values))
                        current_cheat_name = cheat_name_match.group(1).strip()
                        current_values = []
                        continue
                    
                    if line.startswith('040'):
                        parts = line.split()
                        if len(parts) >= 2:
                            values = parts[1:]
                            current_values.append(values)

                if current_cheat_name and current_values:
                    self.cheats.append((current_cheat_name, current_values))

        except FileNotFoundError:
            QMessageBox.warning(self, "Error", f"File {file_path} not found.")
        except Exception as e:
            QMessageBox.warning(self, "Error", f"An error occurred: {e}")

    def enable_selected_cheats(self):
        for checkbox, idx in self.checkboxes:
            if checkbox.isChecked():
                cheat_name, values = self.cheats[idx]
                
                # Here you would implement the logic to apply the cheat using gdb
                for it in values:
                    cheat_code_str = f"0x{it[1]}"
                    cheat_addr_str = f"0x{it[0]}"
                    # cheat_addr = int(cheat_addr_str, 16) + int(gdb.parse_and_eval('$main'))
                    cheat_addr = int(cheat_addr_str, 16)
                    cmd = f"set {{unsigned int}} 0x{cheat_addr:x} = {cheat_code_str}"
                    print(cmd)
                    # gdb.execute(cmd)

                # QMessageBox.information(self, "Success", f"Enabled cheat: {cheat_name}")

    def apply_dark_theme(self):
        dark_stylesheet = """
            QMainWindow {
                background-color: #2E2E2E;
            }
            QWidget {
                background-color: #2E2E2E;
                color: #FFFFFF;
            }
            QCheckBox {
                color: #FFFFFF;
            }
            QPushButton {
                background-color: #4A4A4A;
                color: #FFFFFF;
                border: none;
                padding: 5px;
            }
            QPushButton:hover {
                background-color: #5A5A5A;
            }
            QPushButton:pressed {
                background-color: #6A6A6A;
            }
        """
        self.setStyleSheet(dark_stylesheet)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = CheatManager()
    window.show()
    sys.exit(app.exec_())
