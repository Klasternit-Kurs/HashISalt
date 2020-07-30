using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

namespace HashISalt
{
	/// <summary>
	/// Interaction logic for MainWindow.xaml
	/// </summary>
	public partial class MainWindow : Window
	{
		Sifra s = new Sifra();
		public MainWindow()
		{
			InitializeComponent();
			DataContext = s;
			BindingGroup = new BindingGroup();
		}

		private void Unos(object sender, RoutedEventArgs e)
		{
			BindingGroup.CommitEdit();
			MessageBox.Show(BitConverter.ToString(s.Hash));
		}

		private void Provera(object sender, RoutedEventArgs e)
		{
			if (s.Test(sifra.Text))
				MessageBox.Show("Valid");
			else
				MessageBox.Show("Nope :(");
		}
	}

	public class Sifra
	{
		//Ne cuvamo nikada nigde :)
		private string _sifraCT;
		public string SifraCT 
		{ 
			get => _sifraCT;
			set
			{
				_sifraCT = value;
				SifraCTBajti = Encoding.UTF8.GetBytes(value);
				SHA512Cng enkoder = new SHA512Cng();
				enkoder.ComputeHash(SifraCTBajti);
				Hash = enkoder.Hash;

				Salt = new byte[50];
				RNGCryptoServiceProvider rand = new RNGCryptoServiceProvider();
				rand.GetNonZeroBytes(Salt);
				MessageBox.Show("Salt: " + BitConverter.ToString(Salt));
				
				enkoder.ComputeHash(SaltComb(SifraCTBajti, Salt));
				SaltedHash = enkoder.Hash;
			}
		}
		public byte[] SifraCTBajti { get; set; }
		public byte[] Salt { get; set; }
		public byte[] SifraISalt { get; set; }
		public byte[] Hash { get; set; }
		public byte[] SaltedHash { get; set; }

		public bool Test(string ulaz)
		{
			byte[] UlazBajti = Encoding.UTF8.GetBytes(ulaz);
			SHA512Cng enc = new SHA512Cng();
			enc.ComputeHash(SaltComb(UlazBajti, Salt));

			return Enumerable.SequenceEqual(enc.Hash,SaltedHash);
		}

		public byte[] SaltComb(byte[] sifra, byte[] salt)
		{
			SifraISalt = new byte[sifra.Length + salt.Length];
			Stack<byte> slanikS = new Stack<byte>(salt);
			Stack<byte> sifraS = new Stack<byte>(sifra);
			for (int indeks = 0; indeks < SifraISalt.Length; indeks++)
			{
				if ((indeks + 1) % 3 == 0)
					if (slanikS.Count > 0)
						SifraISalt[indeks] = slanikS.Pop();
					else
						SifraISalt[indeks] = sifraS.Pop();
				else
				{
					if (sifraS.Count > 0)
						SifraISalt[indeks] = sifraS.Pop();
					else
						SifraISalt[indeks] = slanikS.Pop();
				}
			}
			return SifraISalt;
		}
	}
}
