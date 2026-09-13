package io.nekohasekai.sagernet.widget

import android.graphics.Bitmap
import android.graphics.Color
import android.graphics.drawable.GradientDrawable
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ImageView
import android.widget.TextView
import android.widget.Toast
import androidx.core.graphics.ColorUtils
import androidx.core.os.bundleOf
import androidx.core.view.isGone
import androidx.core.view.isVisible
import androidx.fragment.app.DialogFragment
import com.google.android.material.tabs.TabLayout
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.MultiFormatWriter
import com.google.zxing.WriterException
import io.nekohasekai.sagernet.R
import io.nekohasekai.sagernet.SagerNet
import io.nekohasekai.sagernet.ktx.Logs
import io.nekohasekai.sagernet.ktx.dp2px
import io.nekohasekai.sagernet.ktx.readableMessage
import moe.matsuri.nb4a.Protocols.getProtocolColor
import io.nekohasekai.sagernet.ui.MainActivity
import java.nio.charset.StandardCharsets

class QRCodeDialog() : DialogFragment() {

    companion object {
        private const val KEY_URL = "io.nekohasekai.sagernet.QRCodeDialog.KEY_URL"
        private const val KEY_STD_URL = "io.nekohasekai.sagernet.QRCodeDialog.KEY_STD_URL"
        private const val KEY_UNIVERSAL_URL = "io.nekohasekai.sagernet.QRCodeDialog.KEY_UNIVERSAL_URL"
        private const val KEY_NAME = "io.nekohasekai.sagernet.QRCodeDialog.KEY_NAME"
        private const val KEY_TYPE = "io.nekohasekai.sagernet.QRCodeDialog.KEY_TYPE"
        private const val KEY_TYPE_INT = "io.nekohasekai.sagernet.QRCodeDialog.KEY_TYPE_INT"
        private const val KEY_INITIAL_IS_SN = "io.nekohasekai.sagernet.QRCodeDialog.KEY_INITIAL_IS_SN"
        private val iso88591 = StandardCharsets.ISO_8859_1.newEncoder()
    }

    constructor(url: String, displayName: String) : this() {
        arguments = bundleOf(
            KEY_URL to url,
            KEY_NAME to displayName
        )
    }

    constructor(
        stdLink: String?,
        universalLink: String?,
        displayName: String,
        displayType: String? = null,
        typeInt: Int = -1,
        initialIsSn: Boolean = false
    ) : this() {
        arguments = bundleOf(
            KEY_STD_URL to stdLink,
            KEY_UNIVERSAL_URL to universalLink,
            KEY_NAME to displayName,
            KEY_TYPE to displayType,
            KEY_TYPE_INT to typeInt,
            KEY_INITIAL_IS_SN to initialIsSn
        )
    }

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View? {
        return inflater.inflate(R.layout.dialog_qrcode, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        val args = arguments ?: return
        val displayName = args.getString(KEY_NAME) ?: ""
        val displayType = args.getString(KEY_TYPE)
        val typeInt = args.getInt(KEY_TYPE_INT, -1)
        val legacyUrl = args.getString(KEY_URL)

        val stdUrl = args.getString(KEY_STD_URL) ?: if (legacyUrl?.startsWith("sn://") == false) legacyUrl else null
        val universalUrl = args.getString(KEY_UNIVERSAL_URL) ?: if (legacyUrl?.startsWith("sn://") == true) legacyUrl else null

        val tvTitle: TextView = view.findViewById(R.id.tv_qrcode_title)
        val tvType: TextView = view.findViewById(R.id.tv_qrcode_type)
        val btnClose: ImageView = view.findViewById(R.id.btn_close_qrcode)
        val tabs: TabLayout = view.findViewById(R.id.qrcode_tabs)
        val ivQrcode: ImageView = view.findViewById(R.id.iv_qrcode)
        val tvHint: TextView = view.findViewById(R.id.tv_qrcode_format_hint)
        val btnCopy: View = view.findViewById(R.id.btn_copy_qrcode_link)
        val btnDismiss: View = view.findViewById(R.id.btn_dismiss_qrcode)

        tvTitle.text = displayName

        if (!displayType.isNullOrEmpty()) {
            tvType.isVisible = true
            tvType.text = displayType
            if (typeInt >= 0) {
                val protoColor = requireContext().getProtocolColor(typeInt)
                val chipBg = GradientDrawable().apply {
                    cornerRadius = dp2px(6).toFloat()
                    setColor(ColorUtils.setAlphaComponent(protoColor, (255 * 0.12).toInt()))
                }
                tvType.background = chipBg
                tvType.setTextColor(protoColor)
            }
        } else {
            tvType.isGone = true
        }

        btnClose.setOnClickListener { dismiss() }
        btnDismiss.setOnClickListener { dismiss() }

        var currentUrl = stdUrl ?: universalUrl ?: legacyUrl ?: ""

        val hasStd = !stdUrl.isNullOrEmpty()
        val hasUniversal = !universalUrl.isNullOrEmpty()

        tabs.removeAllTabs()

        if (hasStd && hasUniversal) {
            tabs.isVisible = true
            tabs.addTab(tabs.newTab().setText(R.string.qrcode_format_standard))
            tabs.addTab(tabs.newTab().setText(R.string.qrcode_format_sn))
        } else {
            tabs.isGone = true
        }

        fun updateCode(url: String, isSn: Boolean) {
            currentUrl = url
            if (url.isEmpty()) return
            val bmp = generateQrBitmap(url)
            if (bmp != null) {
                ivQrcode.setImageBitmap(bmp)
            }
            tvHint.setText(if (isSn) R.string.qrcode_sn_hint else R.string.qrcode_standard_hint)
        }

        tabs.addOnTabSelectedListener(object : TabLayout.OnTabSelectedListener {
            override fun onTabSelected(tab: TabLayout.Tab) {
                if (tab.position == 0) {
                    stdUrl?.let { updateCode(it, isSn = false) }
                } else {
                    universalUrl?.let { updateCode(it, isSn = true) }
                }
            }

            override fun onTabUnselected(tab: TabLayout.Tab) {}
            override fun onTabReselected(tab: TabLayout.Tab) {}
        })

        // Initial draw
        val preferSn = args.getBoolean(KEY_INITIAL_IS_SN, false)
        val isInitialSn = (preferSn && hasUniversal) || (!hasStd && hasUniversal)
        if (isInitialSn && hasStd && hasUniversal) {
            tabs.getTabAt(1)?.select()
        }
        updateCode(if (isInitialSn) (universalUrl ?: currentUrl) else (if (hasStd) stdUrl!! else (universalUrl ?: currentUrl)), isSn = isInitialSn)

        btnCopy.setOnClickListener {
            if (currentUrl.isNotEmpty()) {
                val success = SagerNet.trySetPrimaryClip(currentUrl)
                Toast.makeText(
                    requireContext(),
                    if (success) R.string.action_export_msg else R.string.action_export_err,
                    Toast.LENGTH_SHORT
                ).show()
            }
        }
    }

    private fun generateQrBitmap(url: String): Bitmap? {
        return try {
            val size = resources.getDimensionPixelSize(R.dimen.qrcode_size)
            val hints = mutableMapOf<EncodeHintType, Any>()
            if (!iso88591.canEncode(url)) {
                hints[EncodeHintType.CHARACTER_SET] = StandardCharsets.UTF_8.name()
            }
            val qrBits = MultiFormatWriter().encode(url, BarcodeFormat.QR_CODE, size, size, hints)
            Bitmap.createBitmap(size, size, Bitmap.Config.RGB_565).apply {
                for (x in 0 until size) {
                    for (y in 0 until size) {
                        setPixel(x, y, if (qrBits.get(x, y)) Color.BLACK else Color.WHITE)
                    }
                }
            }
        } catch (e: WriterException) {
            Logs.w(e)
            (activity as? MainActivity)?.snackbar(e.readableMessage)?.show()
            null
        }
    }

}