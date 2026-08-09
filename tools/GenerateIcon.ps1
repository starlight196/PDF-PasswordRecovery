param(
    [string]$OutputDirectory = (Join-Path $PSScriptRoot "..\assets")
)

$ErrorActionPreference = "Stop"

Add-Type -ReferencedAssemblies System.Drawing.dll -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.IO;

public static class PdfRecoveryIconGenerator
{
    private static readonly int[] IconSizes = new int[] { 16, 20, 24, 32, 40, 48, 64, 128, 256 };

    public static void Generate(string iconPath, string previewPath)
    {
        List<byte[]> images = new List<byte[]>();
        for (int index = 0; index < IconSizes.Length; index++)
        {
            using (Bitmap bitmap = Render(IconSizes[index]))
            using (MemoryStream stream = new MemoryStream())
            {
                bitmap.Save(stream, ImageFormat.Png);
                images.Add(stream.ToArray());
            }
        }

        using (FileStream output = new FileStream(iconPath, FileMode.Create, FileAccess.Write, FileShare.None))
        using (BinaryWriter writer = new BinaryWriter(output))
        {
            writer.Write((ushort)0);
            writer.Write((ushort)1);
            writer.Write((ushort)IconSizes.Length);

            int imageOffset = 6 + (16 * IconSizes.Length);
            for (int index = 0; index < IconSizes.Length; index++)
            {
                int size = IconSizes[index];
                writer.Write((byte)(size == 256 ? 0 : size));
                writer.Write((byte)(size == 256 ? 0 : size));
                writer.Write((byte)0);
                writer.Write((byte)0);
                writer.Write((ushort)1);
                writer.Write((ushort)32);
                writer.Write((uint)images[index].Length);
                writer.Write((uint)imageOffset);
                imageOffset += images[index].Length;
            }

            for (int index = 0; index < images.Count; index++)
                writer.Write(images[index]);
        }

        using (Bitmap preview = Render(512))
            preview.Save(previewPath, ImageFormat.Png);
    }

    private static Bitmap Render(int size)
    {
        Bitmap bitmap = new Bitmap(size, size, PixelFormat.Format32bppArgb);
        using (Graphics graphics = Graphics.FromImage(bitmap))
        {
            graphics.Clear(Color.Transparent);
            graphics.SmoothingMode = SmoothingMode.AntiAlias;
            graphics.PixelOffsetMode = PixelOffsetMode.HighQuality;
            graphics.CompositingQuality = CompositingQuality.HighQuality;
            graphics.ScaleTransform(size / 256f, size / 256f);

            using (GraphicsPath tile = RoundedRectangle(8, 8, 240, 240, 43))
            using (SolidBrush tileBrush = new SolidBrush(Color.FromArgb(29, 38, 44)))
            using (Pen tileBorder = new Pen(Color.FromArgb(54, 68, 77), 4f))
            {
                graphics.FillPath(tileBrush, tile);
                graphics.DrawPath(tileBorder, tile);
            }

            using (GraphicsPath shadow = CreateDocumentPath(59, 41))
            using (SolidBrush shadowBrush = new SolidBrush(Color.FromArgb(70, 0, 0, 0)))
                graphics.FillPath(shadowBrush, shadow);

            using (GraphicsPath document = CreateDocumentPath(53, 35))
            using (SolidBrush paperBrush = new SolidBrush(Color.FromArgb(249, 250, 250)))
            using (Pen paperBorder = new Pen(Color.FromArgb(199, 209, 214), 4f))
            {
                graphics.FillPath(paperBrush, document);
                graphics.DrawPath(paperBorder, document);
            }

            PointF[] foldPoints = new PointF[]
            {
                new PointF(145, 35),
                new PointF(185, 75),
                new PointF(145, 75)
            };
            using (SolidBrush foldBrush = new SolidBrush(Color.FromArgb(218, 225, 229)))
                graphics.FillPolygon(foldBrush, foldPoints);

            using (SolidBrush pdfBrush = new SolidBrush(Color.FromArgb(202, 67, 62)))
            using (GraphicsPath pdfBar = RoundedRectangle(70, 91, 78, 15, 7))
                graphics.FillPath(pdfBrush, pdfBar);

            using (SolidBrush lineBrush = new SolidBrush(Color.FromArgb(139, 152, 160)))
            {
                using (GraphicsPath lineOne = RoundedRectangle(70, 121, 88, 9, 4))
                    graphics.FillPath(lineBrush, lineOne);
                using (GraphicsPath lineTwo = RoundedRectangle(70, 143, 69, 9, 4))
                    graphics.FillPath(lineBrush, lineTwo);
            }

            using (Pen shackle = new Pen(Color.FromArgb(37, 158, 119), 18f))
            using (GraphicsPath shacklePath = new GraphicsPath())
            {
                shackle.StartCap = LineCap.Round;
                shackle.EndCap = LineCap.Round;
                shackle.LineJoin = LineJoin.Round;
                shacklePath.StartFigure();
                shacklePath.AddLine(140, 154, 140, 124);
                shacklePath.AddBezier(140, 124, 140, 88, 177, 76, 195, 103);
                shacklePath.AddLine(195, 103, 207, 91);
                graphics.DrawPath(shackle, shacklePath);
            }

            using (GraphicsPath lockBody = RoundedRectangle(116, 143, 108, 78, 18))
            using (SolidBrush lockBrush = new SolidBrush(Color.FromArgb(24, 121, 93)))
            using (Pen lockBorder = new Pen(Color.FromArgb(13, 79, 60), 4f))
            {
                graphics.FillPath(lockBrush, lockBody);
                graphics.DrawPath(lockBorder, lockBody);
            }

            using (SolidBrush keyholeBrush = new SolidBrush(Color.FromArgb(24, 53, 45)))
            {
                graphics.FillEllipse(keyholeBrush, 161, 164, 19, 19);
                using (GraphicsPath stem = RoundedRectangle(166, 176, 9, 24, 4))
                    graphics.FillPath(keyholeBrush, stem);
            }
        }
        return bitmap;
    }

    private static GraphicsPath CreateDocumentPath(float x, float y)
    {
        GraphicsPath path = new GraphicsPath();
        path.AddPolygon(new PointF[]
        {
            new PointF(x, y),
            new PointF(x + 92, y),
            new PointF(x + 132, y + 40),
            new PointF(x + 132, y + 170),
            new PointF(x, y + 170)
        });
        path.CloseFigure();
        return path;
    }

    private static GraphicsPath RoundedRectangle(float x, float y, float width, float height, float radius)
    {
        GraphicsPath path = new GraphicsPath();
        float diameter = radius * 2f;
        path.AddArc(x, y, diameter, diameter, 180, 90);
        path.AddArc(x + width - diameter, y, diameter, diameter, 270, 90);
        path.AddArc(x + width - diameter, y + height - diameter, diameter, diameter, 0, 90);
        path.AddArc(x, y + height - diameter, diameter, diameter, 90, 90);
        path.CloseFigure();
        return path;
    }
}
'@

$resolvedOutput = [IO.Path]::GetFullPath($OutputDirectory)
[IO.Directory]::CreateDirectory($resolvedOutput) | Out-Null
$iconPath = Join-Path $resolvedOutput "PdfPasswordRecovery.ico"
$previewPath = Join-Path $resolvedOutput "PdfPasswordRecovery.png"

[PdfRecoveryIconGenerator]::Generate($iconPath, $previewPath)
Write-Output "Generated $iconPath"
Write-Output "Generated $previewPath"
