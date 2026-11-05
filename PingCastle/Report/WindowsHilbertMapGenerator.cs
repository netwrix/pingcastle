namespace PingCastle.Report;

using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Net;
using PingCastle.Data;
using PingCastleCommon.Data;
using PingCastleCommon.Utility;

public class WindowsHilbertMapGenerator : IHilbertMapGenerator
{
    public bool TryGenerateHilbertImage(Stream stream, NetworkMapDataView view, NetworkMapData data)
    {
        const int order = 256;
        var uniqueForestSID = new List<string>();
        var subnets = new List<Subnet>();

        foreach (var key in data.NetworkRange.Keys)
        {
            foreach (var subnet in data.NetworkRange[key])
            {
                if (subnet.Network.StartAddress.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
                {
                    continue;
                }

                if (!view.FrameNetwork.MatchIp(subnet.Network.StartAddress) || !view.FrameNetwork.MatchIp(subnet.Network.EndAddress))
                {
                    continue;
                }

                if (subnet.Network.MatchIp(view.FrameNetwork.StartAddress) && subnet.Network.MatchIp(view.FrameNetwork.EndAddress))
                {
                    continue;
                }

                subnets.Add(subnet.Network);
                if (!uniqueForestSID.Contains(key))
                {
                    uniqueForestSID.Add(key);
                }
            }
        }

        if (subnets.Count == 0)
        {
            return false;
        }

        view.RecordCount = subnets.Count;
        view.ForestCount = uniqueForestSID.Count;

        using (Bitmap bitmap = new Bitmap(order, order, System.Drawing.Imaging.PixelFormat.Format32bppArgb))
        using (Graphics g = Graphics.FromImage(bitmap))
        using (SolidBrush drawBrush = new SolidBrush(Color.Black))
        using (SolidBrush dcBrush = new SolidBrush(Color.Red))
        using (StringFormat drawFormat1 = new StringFormat())
        {
            g.Clear(Color.GhostWhite);
            foreach (var s in subnets)
            {
                ulong a = ConvertToN(s.StartAddress, view.FrameNetwork, order);
                ulong b = ConvertToN(s.EndAddress, view.FrameNetwork, order);
                for (ulong i = a; i <= b; i++)
                {
                    int x = 0, y = 0;
                    D2xy(order, (int)i, ref x, ref y);
                    g.FillRectangle(drawBrush, x, y, 1, 1);
                }
            }

            foreach (var dc in data.DomainControllers)
            {
                if (!view.FrameNetwork.MatchIp(dc.Ip))
                {
                    continue;
                }

                ulong a = ConvertToN(dc.Ip, view.FrameNetwork, order);
                int x = 0, y = 0;
                D2xy(order, (int)a, ref x, ref y);
                g.FillRectangle(dcBrush, x, y, 2, 2);
            }

            bitmap.Save(stream, System.Drawing.Imaging.ImageFormat.Png);
        }

        return true;
    }

    private ulong ConvertToN(IPAddress point, Subnet range, int n)
    {
        var v1 = AddressToLong(range.StartAddress);
        var v = AddressToLong(range.EndAddress) - v1;
        return ((ulong)n * (ulong)n * (AddressToLong(point) - v1) / v);
    }

    private ulong AddressToLong(IPAddress a)
    {
        var b = a.GetAddressBytes();
        return ((ulong)b[0] << 24) + ((ulong)b[1] << 16) + ((ulong)b[2] << 8) + (ulong)b[3];
    }

    private int Xy2d(int n, int x, int y)
    {
        int rx, ry, s, d = 0;
        for (s = n / 2; s > 0; s /= 2)
        {
            rx = Convert.ToInt32(((x & s) > 0));
            ry = Convert.ToInt32((y & s) > 0);
            d += s * s * ((3 * rx) ^ ry);
            Rot(s, ref x, ref y, rx, ry);
        }

        return d;
    }

    private void D2xy(int n, int d, ref int x, ref int y)
    {
        int rx, ry, s, t = d;
        x = y = 0;
        for (s = 1; s < n; s *= 2)
        {
            rx = 1 & (t / 2);
            ry = 1 & (t ^ rx);
            Rot(s, ref x, ref y, rx, ry);
            x += s * rx;
            y += s * ry;
            t /= 4;
        }
    }

    private void Rot(int n, ref int x, ref int y, int rx, int ry)
    {
        if (ry == 0)
        {
            if (rx == 1)
            {
                x = n - 1 - x;
                y = n - 1 - y;
            }

            int t = x;
            x = y;
            y = t;
        }
    }
}