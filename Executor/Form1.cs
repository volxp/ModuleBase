using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Diagnostics;
using System.IO.Pipes;
using System.IO;

namespace Executor
{
    public partial class Form1: Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        private void button1_Click(object sender, EventArgs e)
        {
            using (NamedPipeClientStream namedPipeClientStream = new NamedPipeClientStream(".", "CLDYexecution", PipeDirection.InOut))
            {
                try
                {
                    namedPipeClientStream.Connect(5000);
                    byte[] bytes = Encoding.UTF8.GetBytes(fastColoredTextBox1.Text);
                    namedPipeClientStream.Write(bytes, 0, bytes.Length);
                    namedPipeClientStream.Flush();
                    byte[] array = new byte[1024];
                    int count = namedPipeClientStream.Read(array, 0, array.Length);
                    string result = Encoding.UTF8.GetString(array, 0, count);
                }
                catch (TimeoutException)
                {
                    throw new Exception("Connection timeout");
                }
                catch (Exception ex2)
                {
                    throw new Exception("Failed to execute Lua script: " + ex2.Message);
                }
            }
        }

        private void button2_Click(object sender, EventArgs e)
        {
            try
            {
                Process process = new Process
                {
                    StartInfo =
                    {
                        FileName = "Injector.exe",
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }
                };
                process.Start();
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error starting injector: " + ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Hand);
            }
        }
    }
}
